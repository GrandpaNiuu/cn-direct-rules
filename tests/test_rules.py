from __future__ import annotations

import ipaddress
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse
from unittest.mock import patch

from scripts.build import build
from scripts.ruleset import ROOT, load_rules, render_outputs, validate_rules
from scripts.update_sources import (
    LifecyclePolicy,
    can_advance_category,
    download_first,
    download_consensus,
    guard_source_drift,
    normalize_candidate,
    parse_asn_list,
    parse_dnsmasq_domains,
    parse_rir_allocations,
    remove_high_risk_domain_rules,
    repair_domain_redundancy,
    registry_coverage,
    reconcile_values,
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

    def test_major_operator_artifacts_include_both_ip_families(self) -> None:
        outputs = render_outputs(self.rules)
        for operator in ("chinanet", "cmcc", "unicom", "cernet", "cstnet"):
            content = outputs[f"operators/{operator}.conf"]
            self.assertIn("IP-CIDR,", content, operator)
            self.assertIn("IP-CIDR6,", content, operator)
            self.assertNotIn("GEOIP,", content, operator)
            self.assertNotIn("IP-ASN,", content, operator)

    def test_official_registry_artifact_is_published_separately(self) -> None:
        content = render_outputs(self.rules)["registry/cn-allocated.conf"]
        self.assertIn("IP-CIDR,", content)
        self.assertIn("IP-CIDR6,", content)
        self.assertNotIn("GEOIP,", content)
        self.assertNotIn("IP-ASN,", content)

    def test_max_coverage_contains_strict_domains(self) -> None:
        self.assertGreaterEqual(
            len(self.rules.max_domain_suffixes), len(self.rules.domain_suffixes)
        )

    def test_high_risk_foreign_platform_domains_are_not_in_canonical_outputs(self) -> None:
        high_risk = set(
            value
            for value in (ROOT / "config" / "high-risk-domain-suffixes.txt")
            .read_text(encoding="utf-8")
            .splitlines()
            if value and not value.startswith("#")
        )
        canonical = set(self.rules.max_domain_suffixes)
        slipped = sorted(
            value
            for value in canonical
            if any(value == risk or value.endswith("." + risk) for risk in high_risk)
        )
        self.assertEqual([], slipped)
        self.assertTrue(
            set(self.rules.domain_suffixes).issubset(self.rules.max_domain_suffixes)
        )

    def test_shadowrocket_standalone_module_is_complete(self) -> None:
        module = render_outputs(self.rules)["shadowrocket/cn-direct.sgmodule"]
        rule_lines = [
            line
            for line in module.splitlines()
            if line and not line.startswith("#") and line != "[Rule]"
        ]
        expected_rule_count = (
            len(self.rules.max_exact_domains)
            + len(self.rules.max_domain_suffixes)
            + len(self.rules.max_domain_keywords)
            + len(self.rules.ipv4)
            + len(self.rules.ipv6)
            + len(self.rules.asns)
            + 1
        )
        self.assertTrue(module.startswith("#!name="))
        self.assertIn("\n[Rule]\n", module)
        self.assertEqual(expected_rule_count, len(rule_lines))
        self.assertEqual(1, module.count("DOMAIN-SUFFIX,cn,DIRECT"))
        self.assertEqual(1, module.count("GEOIP,CN,DIRECT"))
        self.assertIn("IP-CIDR6,", module)
        self.assertNotIn("GEOSITE,", module.upper())

    def test_shadowrocket_standalone_configuration_is_complete(self) -> None:
        config = render_outputs(self.rules)["shadowrocket/cn-direct.conf"]
        rule_lines = config.split("[Rule]\n", 1)[1].splitlines()
        rule_lines = [line for line in rule_lines if line and not line.startswith("#")]
        expected_rule_count = (
            len(self.rules.max_exact_domains)
            + len(self.rules.max_domain_suffixes)
            + len(self.rules.max_domain_keywords)
            + len(self.rules.ipv4)
            + len(self.rules.ipv6)
            + len(self.rules.asns)
            + 2
        )
        self.assertIn("[General]\n", config)
        self.assertIn("dns-server = system", config)
        self.assertIn("ipv6 = true", config)
        self.assertIn("\n[Rule]\n", config)
        self.assertEqual(expected_rule_count, len(rule_lines))
        self.assertEqual(1, config.count("DOMAIN-SUFFIX,cn,DIRECT"))
        self.assertEqual(1, config.count("GEOIP,CN,DIRECT"))
        self.assertIn("IP-CIDR6,", config)
        self.assertTrue(config.endswith("FINAL,PROXY\n"))
        self.assertNotIn("GEOSITE,", config.upper())

    def test_checksums_cover_every_publishable_file(self) -> None:
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

    def test_update_workflow_commits_without_release_or_tag(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "update.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("git add upstream dist", workflow)
        self.assertIn("git push", workflow)
        for forbidden in (
            "Publish versioned release",
            "gh release",
            "short_sha",
            'tag="rules-',
            "git tag",
        ):
            self.assertNotIn(forbidden, workflow)

    def test_readme_offers_module_and_configuration_install_buttons(self) -> None:
        module_url = (
            "https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/"
            "main/dist/shadowrocket/cn-direct.sgmodule"
        )
        target = f"shadowrocket://install?module={module_url}"
        redirect_url = (
            "https://grandpaniuu.github.io/cn-direct-rules/redirect.html?url="
            + quote(target, safe="")
        )
        config_url = (
            "https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/"
            "main/dist/shadowrocket/cn-direct.conf"
        )
        config_target = f"shadowrocket://config/add/{config_url}"
        config_redirect_url = (
            "https://grandpaniuu.github.io/cn-direct-rules/redirect.html?url="
            + quote(config_target, safe="")
        )
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(redirect_url, readme)
        self.assertIn(config_redirect_url, readme)

        page = (ROOT / "docs" / "redirect.html").read_text(encoding="utf-8")
        self.assertIn(target, page)
        self.assertIn(config_target, page)
        parsed = urlparse(redirect_url)
        self.assertEqual("https", parsed.scheme)
        self.assertEqual(target, parse_qs(parsed.query)["url"][0])
        config_parsed = urlparse(config_redirect_url)
        self.assertEqual(config_target, parse_qs(config_parsed.query)["url"][0])

    def test_pages_workflow_publishes_the_install_redirect(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "pages.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("path: docs", workflow)
        self.assertIn("actions/deploy-pages@", workflow)

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

        with self.assertRaisesRegex(ValueError, "source drift"):
            guard_source_drift(100, 70, 0.2, "example")

    def test_source_normalizer_repairs_duplicate_and_overlapping_cidrs(self) -> None:
        normalized = normalize_candidate(
            "1.0.1.0/24\n1.0.1.0/25\n1.0.1.128/25\n1.0.1.0/24\n",
            4,
            1,
            2,
        )
        self.assertEqual("1.0.1.0/24\n", normalized)

    def test_upstream_failure_keeps_last_verified_snapshot(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "update.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("id: sources", workflow)
        self.assertIn("continue-on-error: true", workflow)
        self.assertIn("steps.sources.outcome == 'failure'", workflow)
        self.assertIn("last verified", workflow.lower())
        self.assertIn("python scripts/build.py", workflow)
        self.assertIn("python scripts/validate.py", workflow)

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

    def test_dnsmasq_and_asn_sources_are_parsed_without_inventing_rules(self) -> None:
        domains = parse_dnsmasq_domains(
            "server=/Example.COM/114.114.114.114\n"
            "#server=/disabled.example/114.114.114.114\n"
            "server=/two.example/114.114.114.114\n"
        )
        asns = parse_asn_list(
            "// generated\nIP-ASN,4134 // China Telecom\nIP-ASN,24429\n"
        )
        self.assertEqual(("example.com", "two.example"), domains)
        self.assertEqual((4134, 24429), asns)

    def test_apnic_registry_records_are_converted_to_exact_cn_networks(self) -> None:
        snapshot = parse_rir_allocations(
            "2|apnic|20260623|10|19830613|20260622|+1000\n"
            "apnic|CN|ipv4|1.0.1.0|256|20110414|allocated\n"
            "apnic|CN|ipv6|2400:3200::|32|20110414|allocated\n"
            "apnic|HK|ipv4|1.2.3.0|256|20110414|allocated\n"
            "apnic|CN|ipv4|1.2.3.0|256|20110414|available\n"
        )
        self.assertEqual("20260623", snapshot.serial_date)
        self.assertEqual(("1.0.1.0/24",), snapshot.ipv4)
        self.assertEqual(("2400:3200::/32",), snapshot.ipv6)

    def test_registry_audit_reports_allocations_missing_from_routed_rules(self) -> None:
        audit = registry_coverage(
            routed=("1.0.1.0/24",),
            registered=("1.0.1.0/24", "1.0.2.0/24"),
        )
        self.assertEqual(512, audit.registered_addresses)
        self.assertEqual(256, audit.missing_addresses)
        self.assertEqual(0.5, audit.missing_ratio)

    def test_rule_is_retired_only_after_consecutive_successful_absences(self) -> None:
        policy = LifecyclePolicy(retire_after_successes=3, max_retire_ratio=0.5)
        first = reconcile_values(
            previous=("a.example", "old.example"),
            observed=("a.example",),
            missing_counts={},
            policy=policy,
        )
        second = reconcile_values(
            previous=first.values,
            observed=("a.example",),
            missing_counts=first.missing_counts,
            policy=policy,
        )
        third = reconcile_values(
            previous=second.values,
            observed=("a.example",),
            missing_counts=second.missing_counts,
            policy=policy,
        )
        self.assertIn("old.example", first.values)
        self.assertIn("old.example", second.values)
        self.assertNotIn("old.example", third.values)
        self.assertEqual(("old.example",), third.retired)

    def test_mass_retirement_is_stopped_by_circuit_breaker(self) -> None:
        with self.assertRaisesRegex(ValueError, "retirement circuit breaker"):
            reconcile_values(
                previous=tuple(f"{value}.example" for value in range(10)),
                observed=("0.example",),
                missing_counts={f"{value}.example": 2 for value in range(1, 10)},
                policy=LifecyclePolicy(
                    retire_after_successes=3, max_retire_ratio=0.2
                ),
            )

    def test_repeated_identical_observation_does_not_age_missing_rules(self) -> None:
        result = reconcile_values(
            previous=("current.example", "missing.example"),
            observed=("current.example",),
            missing_counts={"missing.example": 1},
            policy=LifecyclePolicy(retire_after_successes=3),
            advance_missing=False,
        )
        self.assertEqual({"missing.example": 1}, result.missing_counts)
        self.assertIn("missing.example", result.values)

    def test_redundant_domain_rules_are_repaired_without_waiting_for_retirement(self) -> None:
        repaired = repair_domain_redundancy(
            exact=("literal.net", "www.safe.com"),
            suffixes=("cn", "example.cn", "api.safe.com", "safe.com"),
            missing_counts={
                "domain-exact": {"www.safe.com": 1},
                "domain-suffixes": {"example.cn": 1, "api.safe.com": 1},
            },
        )
        self.assertEqual(("literal.net",), repaired.exact)
        self.assertEqual(("cn", "safe.com"), repaired.suffixes)
        self.assertEqual(
            {"domain-exact": {}, "domain-suffixes": {}}, repaired.missing_counts
        )

    def test_high_risk_domain_rules_are_removed_without_waiting_for_retirement(self) -> None:
        repaired = remove_high_risk_domain_rules(
            exact=("api.google.com", "safe.example"),
            suffixes=("fonts.gstatic.com", "safe.example"),
            high_risk_suffixes={"google.com", "gstatic.com"},
            missing_counts={
                "domain-exact": {"api.google.com": 1, "safe.example": 1},
                "domain-suffixes": {"fonts.gstatic.com": 1, "safe.example": 1},
            },
        )
        self.assertEqual(("safe.example",), repaired.exact)
        self.assertEqual(("safe.example",), repaired.suffixes)
        self.assertEqual(
            {
                "domain-exact": {"safe.example": 1},
                "domain-suffixes": {"safe.example": 1},
            },
            repaired.missing_counts,
        )

    def test_only_a_relevant_source_failure_stops_category_retirement(self) -> None:
        sources = [
            {"id": "domains", "categories": ["domain-suffixes"]},
            {"id": "operator", "categories": ["operator-cmcc-ipv4"]},
        ]
        self.assertTrue(
            can_advance_category(
                sources,
                {"domains": "refreshed", "operator": "retained after refresh failure"},
                "domain-suffixes",
                "2026-06-22",
                "2026-06-23",
            )
        )
        self.assertFalse(
            can_advance_category(
                sources,
                {"domains": "retained after refresh failure", "operator": "refreshed"},
                "domain-suffixes",
                "2026-06-22",
                "2026-06-23",
            )
        )

    def test_audit_only_source_failure_does_not_stop_category_retirement(self) -> None:
        sources = [
            {"id": "domains", "categories": ["domain-suffixes"]},
            {
                "id": "audit-only",
                "categories": ["domain-suffixes"],
                "contributes_to_aggregate": False,
            },
        ]
        self.assertTrue(
            can_advance_category(
                sources,
                {
                    "domains": "refreshed",
                    "audit-only": "retained after refresh failure",
                },
                "domain-suffixes",
                "2026-06-22",
                "2026-06-23",
            )
        )

    def test_checked_in_outputs_are_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            generated = build(Path(directory))
            for relative_name, expected in generated.items():
                checked_in = (ROOT / "dist" / relative_name).read_text(encoding="utf-8")
                self.assertEqual(expected, checked_in, relative_name)


if __name__ == "__main__":
    unittest.main()
