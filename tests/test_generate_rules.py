from __future__ import annotations

import io
import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from urllib.error import URLError

import generate_rules


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


class GenerateRulesTests(unittest.TestCase):
    def test_validate_url_does_not_rewrite_it(self):
        url = (
            "https://github.com/example/project/blob/release/path/rules.txt?plain=1"
        )
        self.assertEqual(generate_rules.validate_url(url), url)

    def test_parse_domains_skips_comments_normalizes_and_deduplicates(self):
        text = "\ufeff# comment\nExample.COM\nexample.com.\n例子.测试\n\n"
        self.assertEqual(
            generate_rules.parse_rules(text, "proxy_domain", "memory"),
            ["example.com", "xn--fsqu00a.xn--0zwm56d"],
        )

    def test_parse_cidr_canonicalizes_and_checks_version(self):
        self.assertEqual(
            generate_rules.parse_rules(
                "192.0.2.12/24\n192.0.2.0/24\n", "direct_ipv4", "memory"
            ),
            ["192.0.2.0/24"],
        )
        with self.assertRaises(generate_rules.RuleValidationError):
            generate_rules.parse_rules("2001:db8::/32", "direct_ipv4", "memory")

    def test_download_retries_and_decodes_utf8_bom(self):
        attempts = 0
        waits = []

        def opener(request, timeout):
            nonlocal attempts
            attempts += 1
            if attempts < 3:
                raise URLError("temporary")
            return FakeResponse("\ufeffexample.com\n".encode("utf-8"))

        result = generate_rules.download_text(
            "https://example.com/rules.txt",
            retry_count=2,
            timeout_seconds=1,
            retry_delay_seconds=0.5,
            opener=opener,
            sleeper=waits.append,
        )
        self.assertEqual(result, "example.com\n")
        self.assertEqual(attempts, 3)
        self.assertEqual(waits, [0.5, 1.0])

    def test_build_outputs_uses_requested_formats_and_headers(self):
        rules = {
            "proxy_domain": ["google.com"],
            "direct_domain": ["baidu.com"],
            "direct_ipv4": ["1.2.4.0/24"],
            "direct_ipv6": ["2a13:1800::/29"],
        }
        updated_at = datetime(2026, 8, 22, 2, 30, 55)
        outputs = generate_rules.build_outputs(rules, updated_at)

        self.assertEqual(
            outputs[Path("Surge/Direct-IPv4.list")],
            "# UPDATED: 2026-08-22 02:30:55\n"
            "# TOTAL: 1\n"
            "IP-CIDR,1.2.4.0/24\n",
        )
        self.assertEqual(
            outputs[Path("Surge/Direct-IPv4_no-resolve.list")],
            "# UPDATED: 2026-08-22 02:30:55\n"
            "# TOTAL: 1\n"
            "IP-CIDR,1.2.4.0/24,no-resolve\n",
        )
        self.assertEqual(
            outputs[Path("Surge/Direct-IPv6_no-resolve.list")],
            "# UPDATED: 2026-08-22 02:30:55\n"
            "# TOTAL: 1\n"
            "IP-CIDR6,2a13:1800::/29,no-resolve\n",
        )
        self.assertIn(
            "HOST-SUFFIX,google.com,Proxy-Domain\n",
            outputs[Path("QuantumultX/Proxy-Domain.list")],
        )
        self.assertIn(
            "IP6-CIDR,2a13:1800::/29,Direct-IPv6\n",
            outputs[Path("QuantumultX/Direct-IPv6.list")],
        )

    def test_collect_rules_merges_multiple_urls_in_order(self):
        sources = {
            kind: (f"https://example.com/{kind}/one",)
            for kind in generate_rules.SOURCE_KINDS
        }
        sources["proxy_domain"] = (
            "https://example.com/proxy_domain/one",
            "https://example.com/proxy_domain/two",
        )
        config = generate_rules.Config(
            sources=sources,
            retry_count=0,
            timeout_seconds=1,
            retry_delay_seconds=0,
            output_directory="rule",
            timezone="UTC",
        )
        payloads = {
            "proxy_domain/one": "first.example\nshared.example\n",
            "proxy_domain/two": "shared.example\nsecond.example\n",
            "direct_domain/one": "direct.example\n",
            "direct_ipv4/one": "192.0.2.0/24\n",
            "direct_ipv6/one": "2001:db8::/32\n",
        }

        def downloader(url, retry_count, timeout_seconds, retry_delay_seconds):
            return payloads[url.removeprefix("https://example.com/")]

        collected = generate_rules.collect_rules(config, downloader=downloader)
        self.assertEqual(
            collected["proxy_domain"],
            ["first.example", "shared.example", "second.example"],
        )

    def test_failed_download_does_not_replace_existing_output(self):
        config = generate_rules.Config(
            sources={kind: (f"https://example.com/{kind}",) for kind in generate_rules.SOURCE_KINDS},
            retry_count=0,
            timeout_seconds=1,
            retry_delay_seconds=0,
            output_directory="rule",
            timezone="UTC",
        )

        def failing_downloader(url, retry_count, timeout_seconds, retry_delay_seconds):
            kind = url.rsplit("/", 1)[-1]
            if kind == "direct_ipv6":
                raise generate_rules.DownloadError("failed")
            return {
                "proxy_domain": "proxy.example\n",
                "direct_domain": "direct.example\n",
                "direct_ipv4": "192.0.2.0/24\n",
            }[kind]

        with tempfile.TemporaryDirectory() as temp_dir:
            previous_cwd = Path.cwd()
            os.chdir(temp_dir)
            try:
                output = Path("rule")
                output.mkdir()
                marker = output / "keep.txt"
                marker.write_text("old", encoding="utf-8")
                with self.assertRaises(generate_rules.DownloadError):
                    generate_rules.generate(
                        config, output, downloader=failing_downloader
                    )
                self.assertEqual(marker.read_text(encoding="utf-8"), "old")
            finally:
                os.chdir(previous_cwd)

    def test_successful_generation_replaces_managed_directory(self):
        config = generate_rules.Config(
            sources={kind: (f"https://example.com/{kind}",) for kind in generate_rules.SOURCE_KINDS},
            retry_count=0,
            timeout_seconds=1,
            retry_delay_seconds=0,
            output_directory="rule",
            timezone="UTC",
        )
        payloads = {
            "proxy_domain": "google.com\n",
            "direct_domain": "baidu.com\n",
            "direct_ipv4": "1.2.4.0/24\n",
            "direct_ipv6": "2a13:1800::/29\n",
        }

        def downloader(url, retry_count, timeout_seconds, retry_delay_seconds):
            return payloads[url.rsplit("/", 1)[-1]]

        with tempfile.TemporaryDirectory() as temp_dir:
            previous_cwd = Path.cwd()
            os.chdir(temp_dir)
            try:
                output = Path("rule")
                output.mkdir()
                (output / "stale.txt").write_text("stale", encoding="utf-8")
                generated = generate_rules.generate(
                    config,
                    output,
                    now=datetime(2026, 8, 22, 2, 30, 55),
                    downloader=downloader,
                )
                self.assertEqual(len(generated), 10)
                self.assertFalse((output / "stale.txt").exists())
                self.assertTrue((output / "Surge/Direct-Domain.list").is_file())
                self.assertTrue(
                    (output / "Surge/Direct-IPv4_no-resolve.list").is_file()
                )
                self.assertTrue(
                    (output / "Surge/Direct-IPv6_no-resolve.list").is_file()
                )
                self.assertTrue(
                    (output / "QuantumultX/Proxy-Domain.list").is_file()
                )
            finally:
                os.chdir(previous_cwd)


if __name__ == "__main__":
    unittest.main()
