from __future__ import annotations

import unittest

from scripts.bgp_origin_audit import (
    build_origin_audit,
    parse_origin_asns,
    parse_origin_lines,
    render_outputs,
)


class BgpOriginAuditTests(unittest.TestCase):
    def test_parse_origin_asns_supports_common_origin_forms(self) -> None:
        self.assertEqual((4134,), parse_origin_asns("4134"))
        self.assertEqual((4134,), parse_origin_asns("AS4134"))
        self.assertEqual((4134, 4809), parse_origin_asns("4134_4809"))
        self.assertEqual((4134, 4809), parse_origin_asns("{4134;4809}"))
        self.assertEqual((), parse_origin_asns("not-an-asn"))

    def test_parse_origin_lines_accepts_prefix_and_caida_style_rows(self) -> None:
        records = parse_origin_lines(
            "\n".join(
                [
                    "1.0.1.0/24 4134",
                    "1.0.2.0 24 AS4809",
                    "2400:3200::/32 4134_4809",
                    "10.0.0.0/8 4134",
                    "bad row",
                ]
            ),
            source="sample",
        )
        self.assertEqual(
            ("1.0.1.0/24", "1.0.2.0/24", "2400:3200::/32"),
            tuple(record.prefix for record in records),
        )
        self.assertEqual((4134, 4809), records[-1].origins)

    def test_build_origin_audit_splits_main_and_rir_only_origins(self) -> None:
        records = (
            *parse_origin_lines("1.0.1.0/24 4134\n1.0.2.0/24 65000\n", source="collector-a"),
            *parse_origin_lines("1.0.1.0/24 4134\n1.0.3.0/24 65000\n", source="collector-b"),
        )
        audit = build_origin_audit(
            records,
            main_asns=(4134,),
            rir_asns=(4134, 65000),
            min_sources=1,
        )
        self.assertEqual(("1.0.1.0/24",), audit.main_prefixes)
        self.assertEqual(("1.0.2.0/24", "1.0.3.0/24"), audit.rir_only_prefixes)
        self.assertEqual((4134,), audit.main_asns_seen)
        self.assertEqual((65000,), audit.rir_only_asns_seen)

    def test_min_sources_filters_unconfirmed_prefixes(self) -> None:
        records = (
            *parse_origin_lines("1.0.1.0/24 4134\n1.0.2.0/24 4134\n", source="collector-a"),
            *parse_origin_lines("1.0.1.0/24 4134\n", source="collector-b"),
        )
        audit = build_origin_audit(records, main_asns=(4134,), rir_asns=(), min_sources=2)
        self.assertEqual(("1.0.1.0/24",), audit.main_prefixes)

    def test_render_outputs_contains_policy_free_audit_warnings(self) -> None:
        records = parse_origin_lines("1.0.1.0/24 4134\n2400:3200::/32 4134\n", source="collector")
        audit = build_origin_audit(records, main_asns=(4134,), rir_asns=(), min_sources=1)
        outputs = render_outputs(audit)
        self.assertIn("IP-CIDR,1.0.1.0/24,DIRECT,no-resolve", outputs["dist/registry/cn-bgp-origin.conf"])
        self.assertIn("IP-CIDR6,2400:3200::/32,DIRECT,no-resolve", outputs["dist/registry/cn-bgp-origin.conf"])
        self.assertIn("BGP observation is an audit signal", outputs["dist/registry/cn-bgp-origin.conf"])


if __name__ == "__main__":
    unittest.main()
