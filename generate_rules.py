#!/usr/bin/env python3
"""Download, merge, validate, and export proxy rules.

The script intentionally uses only Python's standard library so it can run on a
fresh GitHub Actions runner without installing dependencies.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import re
import shutil
import sys
import tempfile
import time
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


LOGGER = logging.getLogger("rule-generator")
DEFAULT_CONFIG_PATH = Path(__file__).with_name("config.json")
SOURCE_KINDS = (
    "proxy_domain",
    "direct_domain",
    "direct_ipv4",
    "direct_ipv6",
)
DOMAIN_LABEL_RE = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\Z")


class RuleGeneratorError(Exception):
    """Base exception for expected generation failures."""


class ConfigError(RuleGeneratorError):
    """Raised when the JSON configuration is invalid."""


class DownloadError(RuleGeneratorError):
    """Raised after an upstream cannot be downloaded after all attempts."""


class RuleValidationError(RuleGeneratorError):
    """Raised when an upstream contains a malformed rule."""


@dataclass(frozen=True)
class Config:
    sources: Mapping[str, tuple[str, ...]]
    retry_count: int
    timeout_seconds: float
    retry_delay_seconds: float
    output_directory: str
    timezone: str


def _require_number(
    value: Any,
    name: str,
    *,
    minimum: float,
    integer: bool = False,
) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{name} 必须是数字")
    if value < minimum:
        raise ConfigError(f"{name} 不能小于 {minimum:g}")
    if integer and not isinstance(value, int):
        raise ConfigError(f"{name} 必须是整数")
    return value


def load_config(path: Path) -> Config:
    """Load and validate a JSON configuration file."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"找不到配置文件：{path}") from exc
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ConfigError(f"无法读取配置文件 {path}：{exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError("配置文件顶层必须是 JSON 对象")

    raw_sources = data.get("sources")
    if not isinstance(raw_sources, dict):
        raise ConfigError("sources 必须是 JSON 对象")

    sources: dict[str, tuple[str, ...]] = {}
    for kind in SOURCE_KINDS:
        urls = raw_sources.get(kind)
        if not isinstance(urls, list) or not urls:
            raise ConfigError(f"sources.{kind} 必须是非空 URL 数组")
        if any(not isinstance(url, str) or not url.strip() for url in urls):
            raise ConfigError(f"sources.{kind} 中的每个 URL 都必须是非空字符串")
        sources[kind] = tuple(url.strip() for url in urls)

    raw_download = data.get("download", {})
    if not isinstance(raw_download, dict):
        raise ConfigError("download 必须是 JSON 对象")

    retry_count = _require_number(
        raw_download.get("retry_count", 3),
        "download.retry_count",
        minimum=0,
        integer=True,
    )
    timeout_seconds = _require_number(
        raw_download.get("timeout_seconds", 30),
        "download.timeout_seconds",
        minimum=0.1,
    )
    retry_delay_seconds = _require_number(
        raw_download.get("retry_delay_seconds", 2),
        "download.retry_delay_seconds",
        minimum=0,
    )

    output_directory = data.get("output_directory", "rule")
    if not isinstance(output_directory, str) or not output_directory.strip():
        raise ConfigError("output_directory 必须是非空字符串")

    timezone_name = data.get("timezone", "Asia/Singapore")
    if not isinstance(timezone_name, str) or not timezone_name.strip():
        raise ConfigError("timezone 必须是非空字符串")
    try:
        ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError as exc:
        raise ConfigError(f"未知时区：{timezone_name}") from exc

    return Config(
        sources=sources,
        retry_count=int(retry_count),
        timeout_seconds=float(timeout_seconds),
        retry_delay_seconds=float(retry_delay_seconds),
        output_directory=output_directory.strip(),
        timezone=timezone_name,
    )


def validate_url(url: str) -> str:
    """Validate an upstream URL without rewriting it."""
    url = url.strip()
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ConfigError(f"仅支持 HTTP/HTTPS URL：{url}")
    return url


def download_text(
    url: str,
    retry_count: int,
    timeout_seconds: float,
    retry_delay_seconds: float,
    *,
    opener: Callable[..., Any] = urlopen,
    sleeper: Callable[[float], None] = time.sleep,
) -> str:
    """Download UTF-8 text, retrying failures with exponential backoff."""
    validated_url = validate_url(url)
    attempts = retry_count + 1
    last_error: Exception | None = None

    for attempt in range(1, attempts + 1):
        request = Request(
            validated_url,
            headers={
                "Accept": "text/plain, application/octet-stream;q=0.9, */*;q=0.1",
                "User-Agent": "rule-set-lite/1.0",
            },
        )
        try:
            with opener(request, timeout=timeout_seconds) as response:
                payload = response.read()
            return payload.decode("utf-8-sig")
        except (HTTPError, URLError, TimeoutError, OSError, UnicodeError) as exc:
            last_error = exc
            if attempt == attempts:
                break
            delay = retry_delay_seconds * (2 ** (attempt - 1))
            LOGGER.warning(
                "下载失败（%d/%d）：%s；%.1f 秒后重试：%s",
                attempt,
                attempts,
                validated_url,
                delay,
                exc,
            )
            if delay:
                sleeper(delay)

    raise DownloadError(
        f"下载失败，已尝试 {attempts} 次：{validated_url}（{last_error}）"
    )


def _normalize_domain(value: str, source: str, line_number: int) -> str:
    candidate = value.rstrip(".").lower()
    if not candidate or any(char.isspace() for char in candidate):
        raise RuleValidationError(f"{source}:{line_number} 域名无效：{value!r}")
    if any(char in candidate for char in (",", "/", "\\", ":")):
        raise RuleValidationError(f"{source}:{line_number} 域名无效：{value!r}")

    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise RuleValidationError(
            f"{source}:{line_number} 域名 IDNA 转换失败：{value!r}"
        ) from exc

    if len(candidate) > 253:
        raise RuleValidationError(f"{source}:{line_number} 域名过长：{value!r}")
    if any(not DOMAIN_LABEL_RE.fullmatch(label) for label in candidate.split(".")):
        raise RuleValidationError(f"{source}:{line_number} 域名无效：{value!r}")

    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return candidate
    raise RuleValidationError(f"{source}:{line_number} 预期域名，却得到 IP：{value!r}")


def _normalize_cidr(
    value: str,
    expected_version: int,
    source: str,
    line_number: int,
) -> str:
    if "/" not in value:
        raise RuleValidationError(f"{source}:{line_number} CIDR 缺少前缀长度：{value!r}")
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise RuleValidationError(
            f"{source}:{line_number} CIDR 无效：{value!r}"
        ) from exc
    if network.version != expected_version:
        raise RuleValidationError(
            f"{source}:{line_number} 预期 IPv{expected_version}，却得到：{value!r}"
        )
    return str(network)


def parse_rules(text: str, kind: str, source: str) -> list[str]:
    """Parse one upstream file, skipping comments and removing duplicates."""
    if kind not in SOURCE_KINDS:
        raise ValueError(f"Unknown rule kind: {kind}")

    rules: list[str] = []
    seen: set[str] = set()
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        value = raw_line.strip().lstrip("\ufeff")
        if not value or value.startswith("#"):
            continue

        if kind.endswith("domain"):
            normalized = _normalize_domain(value, source, line_number)
        elif kind == "direct_ipv4":
            normalized = _normalize_cidr(value, 4, source, line_number)
        else:
            normalized = _normalize_cidr(value, 6, source, line_number)

        if normalized not in seen:
            seen.add(normalized)
            rules.append(normalized)

    if not rules:
        raise RuleValidationError(f"上游没有有效规则：{source}")
    return rules


def merge_unique(groups: Iterable[Iterable[str]]) -> list[str]:
    """Merge rule groups while preserving first-seen order."""
    merged: list[str] = []
    seen: set[str] = set()
    for group in groups:
        for rule in group:
            if rule not in seen:
                seen.add(rule)
                merged.append(rule)
    return merged


def collect_rules(
    config: Config,
    *,
    downloader: Callable[[str, int, float, float], str] = download_text,
) -> dict[str, list[str]]:
    """Download every configured source before any output is published."""
    collected: dict[str, list[str]] = {}
    for kind in SOURCE_KINDS:
        groups: list[list[str]] = []
        for url in config.sources[kind]:
            LOGGER.info("下载 %s：%s", kind, url)
            text = downloader(
                url,
                config.retry_count,
                config.timeout_seconds,
                config.retry_delay_seconds,
            )
            parsed = parse_rules(text, kind, url)
            LOGGER.info("读取 %d 条有效规则：%s", len(parsed), url)
            groups.append(parsed)
        collected[kind] = merge_unique(groups)
        LOGGER.info("%s 合并后共 %d 条", kind, len(collected[kind]))
    return collected


def _render_file(rules: list[str], updated_at: datetime) -> str:
    lines = [
        f"# UPDATED: {updated_at.strftime('%Y-%m-%d %H:%M:%S')}",
        f"# TOTAL: {len(rules)}",
        *rules,
    ]
    return "\n".join(lines) + "\n"


def build_outputs(
    rules: Mapping[str, list[str]],
    updated_at: datetime,
) -> dict[Path, str]:
    """Build all Surge and Quantumult X files in memory."""
    surge_direct_domains = [f"DOMAIN-SUFFIX,{item}" for item in rules["direct_domain"]]
    surge_proxy_domains = [f"DOMAIN-SUFFIX,{item}" for item in rules["proxy_domain"]]
    surge_ipv4 = [f"IP-CIDR,{item}" for item in rules["direct_ipv4"]]
    surge_ipv6 = [f"IP-CIDR6,{item}" for item in rules["direct_ipv6"]]
    surge_ipv4_no_resolve = [
        f"IP-CIDR,{item},no-resolve" for item in rules["direct_ipv4"]
    ]
    surge_ipv6_no_resolve = [
        f"IP-CIDR6,{item},no-resolve" for item in rules["direct_ipv6"]
    ]

    qx_direct_domains = [
        f"HOST-SUFFIX,{item},Direct-Domain" for item in rules["direct_domain"]
    ]
    qx_proxy_domains = [
        f"HOST-SUFFIX,{item},Proxy-Domain" for item in rules["proxy_domain"]
    ]
    qx_ipv4 = [f"IP-CIDR,{item},Direct-IPv4" for item in rules["direct_ipv4"]]
    qx_ipv6 = [f"IP6-CIDR,{item},Direct-IPv6" for item in rules["direct_ipv6"]]

    return {
        Path("Surge/Direct-Domain.list"): _render_file(
            surge_direct_domains, updated_at
        ),
        Path("Surge/Direct-IPv4.list"): _render_file(surge_ipv4, updated_at),
        Path("Surge/Direct-IPv4_no-resolve.list"): _render_file(
            surge_ipv4_no_resolve, updated_at
        ),
        Path("Surge/Direct-IPv6.list"): _render_file(surge_ipv6, updated_at),
        Path("Surge/Direct-IPv6_no-resolve.list"): _render_file(
            surge_ipv6_no_resolve, updated_at
        ),
        Path("Surge/Proxy-Domain.list"): _render_file(
            surge_proxy_domains, updated_at
        ),
        Path("QuantumultX/Direct-Domain.list"): _render_file(
            qx_direct_domains, updated_at
        ),
        Path("QuantumultX/Direct-IPv4.list"): _render_file(qx_ipv4, updated_at),
        Path("QuantumultX/Direct-IPv6.list"): _render_file(qx_ipv6, updated_at),
        Path("QuantumultX/Proxy-Domain.list"): _render_file(
            qx_proxy_domains, updated_at
        ),
    }


def publish_outputs(outputs: Mapping[Path, str], output_directory: Path) -> None:
    """Replace the managed output directory transactionally."""
    target = output_directory.resolve()
    workspace = Path.cwd().resolve()
    if target == workspace or workspace not in target.parents:
        raise ConfigError("输出目录必须位于当前工作目录内，且不能是工作目录本身")
    if target.is_symlink():
        raise ConfigError(f"拒绝覆盖符号链接输出目录：{target}")

    target.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{target.name}.staging-", dir=target.parent)
    )
    backup = target.parent / f".{target.name}.backup-{uuid.uuid4().hex}"
    moved_existing = False

    try:
        for relative_path, content in outputs.items():
            destination = staging / relative_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(content, encoding="utf-8", newline="\n")

        if target.exists():
            if not target.is_dir():
                raise ConfigError(f"输出路径存在但不是目录：{target}")
            target.replace(backup)
            moved_existing = True

        try:
            staging.replace(target)
        except Exception:
            if moved_existing and backup.exists() and not target.exists():
                backup.replace(target)
            raise

        if backup.exists():
            shutil.rmtree(backup)
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def generate(
    config: Config,
    output_directory: Path,
    *,
    now: datetime | None = None,
    downloader: Callable[[str, int, float, float], str] = download_text,
) -> dict[Path, str]:
    """Run a complete generation and return the rendered outputs."""
    rules = collect_rules(config, downloader=downloader)
    updated_at = now or datetime.now(ZoneInfo(config.timezone))
    outputs = build_outputs(rules, updated_at)
    publish_outputs(outputs, output_directory)
    return outputs


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="生成 Surge 和 Quantumult X 规则文件")
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help=f"JSON 配置文件（默认：{DEFAULT_CONFIG_PATH.name}）",
    )
    parser.add_argument("--output-directory", type=Path, help="覆盖配置中的输出目录")
    parser.add_argument("--retry-count", type=int, help="覆盖每个 URL 的额外重试次数")
    parser.add_argument("--timeout", type=float, help="覆盖单次下载超时秒数")
    parser.add_argument("--retry-delay", type=float, help="覆盖首次重试等待秒数")
    parser.add_argument("--timezone", help="覆盖更新时间所用 IANA 时区")
    return parser


def _apply_overrides(config: Config, args: argparse.Namespace) -> Config:
    retry_count = config.retry_count if args.retry_count is None else args.retry_count
    timeout = config.timeout_seconds if args.timeout is None else args.timeout
    retry_delay = (
        config.retry_delay_seconds if args.retry_delay is None else args.retry_delay
    )
    timezone_name = config.timezone if args.timezone is None else args.timezone

    _require_number(retry_count, "--retry-count", minimum=0, integer=True)
    _require_number(timeout, "--timeout", minimum=0.1)
    _require_number(retry_delay, "--retry-delay", minimum=0)
    try:
        ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError as exc:
        raise ConfigError(f"未知时区：{timezone_name}") from exc

    return Config(
        sources=config.sources,
        retry_count=retry_count,
        timeout_seconds=timeout,
        retry_delay_seconds=retry_delay,
        output_directory=config.output_directory,
        timezone=timezone_name,
    )


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    args = build_argument_parser().parse_args(argv)
    try:
        config = _apply_overrides(load_config(args.config), args)
        output_directory = args.output_directory or Path(config.output_directory)
        outputs = generate(config, output_directory)
    except RuleGeneratorError as exc:
        LOGGER.error("%s", exc)
        return 1
    except OSError as exc:
        LOGGER.error("文件操作失败：%s", exc)
        return 1

    LOGGER.info("生成完成：%s（%d 个文件）", output_directory, len(outputs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
