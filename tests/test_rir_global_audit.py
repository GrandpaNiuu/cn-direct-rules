from __future__ import annotations

import unittest

from scripts.rir_global_audit import asn_diff, combine_snapshots, parse_delegated, render_outputs


class RirGlobalAuditTests(unittest.TestCase):
    def test_parse_delegated_extracts_cn_ip_and_asn_records(self) -> None:
        snapshot = parse_delegated(
            "\n".join(
                [
                    "2|apnic|20260623|6|19830613|20260622|+1000",
                    "apnic|CN|ipv4|1.0.1.0|256|20110414|allocated",
                    "apnic|CN|ipv6|2400:3200::|32|20110414|assigned",
                    "apnic|CN|asn|4134|2|19950701|allocated",
                    "apnic|HK|asn|999|1|19950701|allocated",
                    "apnic|CN|ipv4|1.2.3.0|256|20110414|available",
                ]
            ),
            registry="apnic",
        )
        self.assertEqual("20260623", snapshot.serial_date)
        self.assertEqual(("1.0.1.0/24",), snapshot.ipv4)
        self.assertEqual(("2400:3200::/32",), snapshot.ipv6)
        self.assertEqual((4134, 4135), snapshot.asns)

    def test_parse_delegated_rejects_missing_header(self) -> None:
        with self.assertRaisesRegex(ValueError, "serial date"):
            parse_delegated("apnic|CN|asn|4134|1|19950701|allocated\n", registry="apnic")

    def test_combined_outputs_and_asn_diff_are_deterministic(self) -> None:
        first = parse_delegated(
            "2|apnic|20260623|2|19830613|20260622|+1000\n"
            "apnic|CN|ipv4|1.0.1.0|256|20110414|allocated\n"
            "apnic|CN|asn|4134|1|19950701|allocated\n",
            registry="apnic",
        )
        second = parse_delegated(
            "2|arin|20260623|2|19830613|20260622|-0500\n"
            "arin|CN|ipv4|1.0.2.0|256|20110414|allocated\n"
            "arin|CN|asn|4809|1|19950701|assigned\n",
            registry="arin",
        )
        audit = combine_snapshots((second, first))
        self.assertEqual(("1.0.1.0/24", "1.0.2.0/24"), audit.ipv4)
        self.assertEqual((4134, 4809), audit.asns)
        self.assertEqual(
            {"main": 2, "rir": 2, "intersection": 1, "only_in_main": 1, "only_in_rir": 1},
            asn_diff((4134, 24429), audit.asns)["counts"],
        )
        outputs = render_outputs(audit)
        self.assertIn("IP-CIDR,1.0.1.0/24,DIRECT,no-resolve", outputs["dist/registry/cn-global-allocated.conf"])
        self.assertIn("IP-ASN,4809,DIRECT", outputs["dist/registry/cn-rir-asn.conf"])


if __name__ == "__main__":
    unittest.main()
