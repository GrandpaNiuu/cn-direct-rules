from __future__ import annotations

import ipaddress
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from scripts.build import build
from scripts.ruleset import ROOT, load_rules, render_outputs, validate_rules
from scripts.update_sources import (
    download_first,
    download_consensus,
    normalize_candidate,
    resolve_domain_files,
)


class RuleRepositoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rules = load_rules()

    def test_repository_model_is_valid(self) -> None:
        self.assertEqual([], validate_rules(self.rules))

    def test_required_portability_contract(self) -> None:
        outputs = render_outputs(self.rules)
        full = outputs["cn.conf"]
        self.assertEqual(1, full.count("DOMAIN-SUFFIX,cn,DIRECT"))
        self.assertEqual(1, full.count("GEOIP,CN,DIRECT"))
        self.assertNotIn("GEOSITE,", "\n".join(outputs.values()).upper())
        self.assertNotIn(",DIRECT", outputs["clash/cn.yaml"])
        self.assertNotIn(",DIRECT", outputs["rule-set/cn.list"])
        self.assertNotIn(",DIRECT", outputs["rule-set/cn-max.list"])

    def test_max_coverage_contains_strict_domains(self) -> None:
        self.assertGreaterEqual(
            len(self.rules.max_domain_suffixes), len(self.rules.domain_suffixes)
        )
        self.assertTrue(
            set(self.rules.domain_suffixes).issubset(self.rules.max_domain_suffixes)
        )

    def test_release_checksums_cover_every_publishable_file(self) -> None:
        outputs = render_outputs(self.rules)
        checksummed = {
            line.split("  ", 1)[1]
            for line in outputs["SHA256SUMS"].splitlines()
            if line
        }
        self.assertEqual(set(outputs) - {"SHA256SUMS"}, checksummed)

    def test_daily_schedule_is_midnight_in_shanghai(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "update.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn('cron: "0 16 * * *"', workflow)

    def test_private_network_is_rejected(self) -> None:
        invalid = replace(
            self.rules,
            ipv4=(ipaddress.ip_network("10.0.0.0/8"), *self.rules.ipv4),
        )
        errors = validate_rules(invalid)
        self.assertTrue(any("non-public network" in error for error in errors))

    def test_source_drift_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "outside"):
            normalize_candidate("1.0.1.0/24\n", 4, 5000, 7000)

    @patch("scripts.update_sources.download")
    def test_source_download_falls_back_to_second_mirror(self, mocked_download) -> None:
        mocked_download.side_effect = [RuntimeError("primary unavailable"), b"mirror"]
        payload, url = download_first(
            ["https://primary.invalid/list", "https://mirror.invalid/list"], 1024
        )
        self.assertEqual(b"mirror", payload)
        self.assertEqual("https://mirror.invalid/list", url)

    @patch("scripts.update_sources.download")
    def test_source_mirror_disagreement_is_rejected(self, mocked_download) -> None:
        mocked_download.side_effect = [b"first", b"second"]
        with self.assertRaisesRegex(ValueError, "mirrors disagree"):
            download_consensus(
                ["https://first.invalid/list", "https://second.invalid/list"], 1024
            )

    def test_domain_resolver_honors_types_includes_and_attribute_filters(self) -> None:
        files = {
            "cn": "include:tld\ninclude:geo\n",
            "tld": "cn\n",
            "geo": (
                "include:vendor @-!cn\n"
                "full:api.example.cn\n"
                "keyword:mainland-app\n"
                "regexp:^unsupported\\.example$\n"
            ),
            "vendor": "example.cn\nexcluded.example @!cn\n",
        }
        snapshot = resolve_domain_files(files, "cn")
        self.assertEqual(("api.example.cn",), snapshot.exact)
        self.assertEqual(("cn", "example.cn"), snapshot.suffixes)
        self.assertEqual(("mainland-app",), snapshot.keywords)
        self.assertEqual(1, snapshot.skipped_regexes)

    def test_checked_in_outputs_are_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            generated = build(Path(directory))
            for relative_name, expected in generated.items():
                checked_in = (ROOT / "dist" / relative_name).read_text(encoding="utf-8")
                self.assertEqual(expected, checked_in, relative_name)


if __name__ == "__main__":
    unittest.main()
