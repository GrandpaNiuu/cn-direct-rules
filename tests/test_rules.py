from __future__ import annotations

import ipaddress
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from scripts.build import build
from scripts.ruleset import ROOT, load_rules, render_outputs, validate_rules
from scripts.update_sources import normalize_candidate


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

    def test_checked_in_outputs_are_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            generated = build(Path(directory))
            for relative_name, expected in generated.items():
                checked_in = (ROOT / "dist" / relative_name).read_text(encoding="utf-8")
                self.assertEqual(expected, checked_in, relative_name)


if __name__ == "__main__":
    unittest.main()
