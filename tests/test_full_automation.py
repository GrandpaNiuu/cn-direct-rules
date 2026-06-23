from __future__ import annotations

import gzip
import unittest

from scripts.bgp_auto import build_audit, parse_origin_asns, parse_pfx2as
from scripts.issue_auto_triage import decide
from scripts.ruleset import ROOT


class FullAutomationTests(unittest.TestCase):
    def test_main_workflow_runs_rir_and_bgp_audits(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "update.yml").read_text(encoding="utf-8")
        self.assertIn("python scripts/auto_maintain.py", workflow)
        self.assertIn("python scripts/bgp_auto.py", workflow)
        self.assertIn("python scripts/build.py", workflow)
        self.assertIn("python scripts/validate.py", workflow)

    def test_bgp_pfx2as_parser_accepts_multi_origin_records(self) -> None:
        payload = gzip.compress(b"1.0.1.0\t24\t4134_4809\n10.0.0.0\t8\t4134\n")
        records = parse_pfx2as(payload)
        self.assertEqual(1, len(records))
        self.assertEqual("1.0.1.0/24", records[0].prefix)
        self.assertEqual((4134, 4809), records[0].origins)
        self.assertEqual((4134, 4809), parse_origin_asns("AS4134,4809"))

    def test_bgp_audit_allows_more_specific_overlaps(self) -> None:
        payload = gzip.compress(b"1.0.0.0\t16\t4134\n1.0.1.0\t24\t4134\n")
        records = parse_pfx2as(payload)
        audit = build_audit(records, main_asns=(4134,), rir_asns=(), source_url="local", sha256="test")
        self.assertEqual(("1.0.0.0/16", "1.0.1.0/24"), audit.main_prefixes)

    def test_issue_auto_triage_classifies_valid_and_incomplete_reports(self) -> None:
        incomplete = decide("missing: example.cn", "")
        self.assertEqual("needs-info", incomplete.label)
        body = "### Missing target\nexample.cn\n### Target type\ndomain\n### Evidence\nOfficial public site.\n"
        accepted = decide("missing: example.cn", body)
        self.assertEqual("ready-for-agent", accepted.label)
        self.assertFalse(accepted.close)


if __name__ == "__main__":
    unittest.main()
