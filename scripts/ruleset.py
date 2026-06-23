from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
DATA_NOTICE = (
    "# Data provenance and licenses: "
    "https://github.com/GrandpaNiuu/cn-direct-rules/blob/main/DATA_LICENSE.md"
)


@dataclass(frozen=True)
class RuleSet:
    exact_domains: tuple[str, ...]
    domain_suffixes: tuple[str, ...]
    domain_keywords: tuple[str, ...]
    max_exact_domains: tuple[str, ...]
    max_domain_suffixes: tuple[str, ...]
    max_domain_keywords: tuple[str, ...]
    domain_source_sha256: str
    skipped_domain_regexes: int
    ipv4: tuple[ipaddress.IPv4Network, ...]
    ipv6: tuple[ipaddress.IPv6Network, ...]
    asns: tuple[int, ...]
    operator_networks: dict[str, tuple[ipaddress._BaseNetwork, ...]]
    registry_networks: tuple[ipaddress._BaseNetwork, ...]


def read_values(path: Path) -> tuple[str, ...]:
    return tuple(
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


def load_rules(root: Path = ROOT) -> RuleSet:
    upstream_exact = read_values(root / "upstream" / "domain-exact.txt")
    upstream_suffixes = read_values(root / "upstream" / "domain-suffixes.txt")
    upstream_keywords = read_values(root / "upstream" / "domain-keywords.txt")
    domain_metadata = json.loads(
        (root / "upstream" / "domain-metadata.json").read_text(encoding="utf-8")
    )
    forbidden = set(read_values(root / "config" / "forbidden-domain-suffixes.txt"))
    source_config = json.loads(
        (root / "config" / "sources.json").read_text(encoding="utf-8")
    )
    operator_networks: dict[str, tuple[ipaddress._BaseNetwork, ...]] = {}
    registry_networks: list[ipaddress._BaseNetwork] = []
    for source in source_config["sources"]:
        if source["kind"] == "rir-statistics":
            for category in source["categories"]:
                registry_networks.extend(
                    ipaddress.ip_network(value, strict=True)
                    for value in read_values(
                        root
                        / "upstream"
                        / "sources"
                        / source["id"]
                        / f"{category}.txt"
                    )
                )
            continue
        if source["kind"] != "mixed-cidr":
            continue
        operator = source["category_prefix"].removeprefix("operator-")
        values: list[ipaddress._BaseNetwork] = []
        for category in source["categories"]:
            values.extend(
                ipaddress.ip_network(value, strict=True)
                for value in read_values(
                    root / "upstream" / "sources" / source["id"] / f"{category}.txt"
                )
            )
        operator_networks[operator] = tuple(
            sorted(values, key=lambda network: (network.version, *network_sort_key(network)))
        )

    max_exact = tuple(sorted(set(upstream_exact), key=str.casefold))
    max_suffixes = tuple(sorted(set(upstream_suffixes), key=str.casefold))
    max_keywords = tuple(sorted(set(upstream_keywords), key=str.casefold))
    strict_suffixes = tuple(value for value in max_suffixes if value not in forbidden)

    return RuleSet(
        exact_domains=max_exact,
        domain_suffixes=strict_suffixes,
        domain_keywords=max_keywords,
        max_exact_domains=max_exact,
        max_domain_suffixes=max_suffixes,
        max_domain_keywords=max_keywords,
        domain_source_sha256=hashlib.sha256(
            "\n".join(
                (
                    *upstream_exact,
                    "--suffixes--",
                    *upstream_suffixes,
                    "--keywords--",
                    *upstream_keywords,
                )
            ).encode("utf-8")
        ).hexdigest(),
        skipped_domain_regexes=int(domain_metadata["skipped_regexes"]),
        ipv4=tuple(
            ipaddress.ip_network(value, strict=True)
            for value in read_values(root / "upstream" / "ipv4.txt")
        ),
        ipv6=tuple(
            ipaddress.ip_network(value, strict=True)
            for value in read_values(root / "upstream" / "ipv6.txt")
        ),
        asns=tuple(int(value) for value in read_values(root / "upstream" / "asns.txt")),
        operator_networks=operator_networks,
        registry_networks=tuple(
            sorted(
                registry_networks,
                key=lambda network: (network.version, *network_sort_key(network)),
            )
        ),
    )


def network_sort_key(network: ipaddress._BaseNetwork) -> tuple[int, int]:
    return int(network.network_address), network.prefixlen


def _check_sorted_unique(
    name: str, values: Iterable[str | int], *, numeric: bool = False
) -> list[str]:
    materialized = list(values)
    expected = sorted(set(materialized), key=(int if numeric else lambda value: str(value).casefold()))
    if materialized != expected:
        return [f"{name} must be sorted and contain no duplicates"]
    return []


def _check_domain(name: str, value: str) -> str | None:
    if value != value.strip() or not value or "," in value or value.startswith("."):
        return f"invalid {name}: {value!r}"
    try:
        ascii_value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return f"invalid IDN in {name}: {value!r}"
    if len(ascii_value) > 253 or any(
        not label or len(label) > 63 for label in ascii_value.split(".")
    ):
        return f"invalid {name}: {value!r}"
    return None


def validate_networks(
    networks: tuple[ipaddress._BaseNetwork, ...], version: int
) -> list[str]:
    errors: list[str] = []
    if any(network.version != version for network in networks):
        errors.append(f"IPv{version} source contains a network from another address family")
    expected = tuple(sorted(set(networks), key=network_sort_key))
    if networks != expected:
        errors.append(f"IPv{version} source must be numerically sorted and contain no duplicates")

    maximum_end = -1
    for network in networks:
        if not network.is_global:
            errors.append(f"IPv{version} source contains non-public network {network}")
        start = int(network.network_address)
        end = int(network.broadcast_address)
        if start <= maximum_end:
            errors.append(f"IPv{version} source contains overlapping network {network}")
        maximum_end = max(maximum_end, end)
    return errors


def validate_rules(rules: RuleSet, root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    for label, relative_path in (
        ("upstream exact domains", "upstream/domain-exact.txt"),
        ("upstream domain suffixes", "upstream/domain-suffixes.txt"),
        ("upstream domain keywords", "upstream/domain-keywords.txt"),
    ):
        errors.extend(_check_sorted_unique(label, read_values(root / relative_path)))
    errors.extend(
        _check_sorted_unique(
            "upstream ASNs", read_values(root / "upstream" / "asns.txt"), numeric=True
        )
    )

    errors.extend(_check_sorted_unique("exact domains", rules.exact_domains))
    errors.extend(_check_sorted_unique("domain suffixes", rules.domain_suffixes))
    errors.extend(_check_sorted_unique("domain keywords", rules.domain_keywords))
    errors.extend(_check_sorted_unique("max exact domains", rules.max_exact_domains))
    errors.extend(_check_sorted_unique("max domain suffixes", rules.max_domain_suffixes))
    errors.extend(_check_sorted_unique("max domain keywords", rules.max_domain_keywords))
    errors.extend(_check_sorted_unique("ASNs", rules.asns, numeric=True))

    for name, values in (
        ("exact domain", rules.exact_domains),
        ("domain suffix", rules.domain_suffixes),
        ("max exact domain", rules.max_exact_domains),
        ("max domain suffix", rules.max_domain_suffixes),
    ):
        errors.extend(
            error for value in values if (error := _check_domain(name, value)) is not None
        )

    if any(not keyword or "," in keyword or keyword != keyword.strip() for keyword in rules.domain_keywords):
        errors.append("domain keywords contain an empty, malformed, or whitespace-padded value")
    if any(
        not keyword or "," in keyword or keyword != keyword.strip()
        for keyword in rules.max_domain_keywords
    ):
        errors.append("max domain keywords contain a malformed value")
    if any(asn <= 0 for asn in rules.asns):
        errors.append("ASNs must be positive integers")

    if rules.domain_suffixes.count("cn") != 1:
        errors.append("domain suffix 'cn' must appear exactly once")
    if rules.max_domain_suffixes.count("cn") != 1:
        errors.append("max domain suffix 'cn' must appear exactly once")
    forbidden = set(read_values(root / "config" / "forbidden-domain-suffixes.txt"))
    unsafe = sorted(forbidden.intersection(rules.domain_suffixes))
    if unsafe:
        errors.append(f"unsafe global suffixes cannot be routed wholesale: {', '.join(unsafe)}")
    high_risk = set(read_values(root / "config" / "high-risk-domain-suffixes.txt"))
    risky = sorted(
        value
        for value in rules.max_domain_suffixes
        if any(value == root_suffix or value.endswith("." + root_suffix) for root_suffix in high_risk)
    )
    if risky:
        errors.append(
            "high-risk foreign-platform suffixes cannot be routed in canonical outputs: "
            + ", ".join(risky[:20])
        )
    if not set(rules.domain_suffixes).issubset(rules.max_domain_suffixes):
        errors.append("max domain suffixes must contain every strict suffix")

    errors.extend(validate_networks(rules.ipv4, 4))
    errors.extend(validate_networks(rules.ipv6, 6))
    for operator, networks in rules.operator_networks.items():
        operator_v4 = tuple(network for network in networks if network.version == 4)
        operator_v6 = tuple(network for network in networks if network.version == 6)
        errors.extend(
            f"operator {operator}: {error}"
            for error in (*validate_networks(operator_v4, 4), *validate_networks(operator_v6, 6))
        )
    registry_v4 = tuple(network for network in rules.registry_networks if network.version == 4)
    registry_v6 = tuple(network for network in rules.registry_networks if network.version == 6)
    errors.extend(
        f"registry: {error}"
        for error in (*validate_networks(registry_v4, 4), *validate_networks(registry_v6, 6))
    )
    if tuple(ipaddress.collapse_addresses((*rules.ipv4, *registry_v4))) != rules.ipv4:
        errors.append("official registry IPv4 is not contained in canonical coverage")
    if tuple(ipaddress.collapse_addresses((*rules.ipv6, *registry_v6))) != rules.ipv6:
        errors.append("official registry IPv6 is not contained in canonical coverage")

    source_config = json.loads((root / "config" / "sources.json").read_text(encoding="utf-8"))
    aggregate_bounds = source_config["aggregate_bounds"]
    for name, values in (("ipv4", rules.ipv4), ("ipv6", rules.ipv6)):
        bounds = aggregate_bounds[name]
        if not bounds["min_entries"] <= len(values) <= bounds["max_entries"]:
            errors.append(
                f"{name} count {len(values)} is outside the allowed range "
                f"{bounds['min_entries']}..{bounds['max_entries']}"
            )
    upstream_domain_counts = {
        "exact": len(read_values(root / "upstream" / "domain-exact.txt")),
        "suffixes": len(read_values(root / "upstream" / "domain-suffixes.txt")),
        "keywords": len(read_values(root / "upstream" / "domain-keywords.txt")),
    }
    domain_total = sum(upstream_domain_counts.values())
    domain_bounds = aggregate_bounds["domain"]
    if not domain_bounds["min_entries"] <= domain_total <= domain_bounds["max_entries"]:
        errors.append(
            f"domain source count {domain_total} is outside "
            f"{domain_bounds['min_entries']}..{domain_bounds['max_entries']}"
        )
    metadata = json.loads(
        (root / "upstream" / "domain-metadata.json").read_text(encoding="utf-8")
    )
    for name, count in upstream_domain_counts.items():
        if metadata.get(name) != count:
            errors.append(f"domain metadata count mismatch for {name}")
    skipped_regexes = metadata.get("skipped_regexes")
    if not isinstance(skipped_regexes, int) or not 0 <= skipped_regexes <= 100:
        errors.append("domain metadata skipped_regexes must be an integer from 0 to 100")
    elif rules.skipped_domain_regexes != skipped_regexes:
        errors.append("domain metadata skipped_regexes does not match the loaded rules")

    asn_bounds = aggregate_bounds["asn"]
    if not asn_bounds["min_entries"] <= len(rules.asns) <= asn_bounds["max_entries"]:
        errors.append(
            f"asn count {len(rules.asns)} is outside the allowed range "
            f"{asn_bounds['min_entries']}..{asn_bounds['max_entries']}"
        )
    configured_ids = {source["id"] for source in source_config["sources"]}
    report_path = root / "upstream" / "update-report.json"
    if not report_path.exists():
        errors.append("missing upstream/update-report.json")
    else:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        if set(report.get("sources", {})) != configured_ids:
            errors.append("update report does not cover every configured source")
        expected_report_counts = {
            "exact": upstream_domain_counts["exact"],
            "suffixes": upstream_domain_counts["suffixes"],
            "keywords": upstream_domain_counts["keywords"],
            "skipped_regexes": skipped_regexes,
            "ipv4": len(rules.ipv4),
            "ipv6": len(rules.ipv6),
            "asns": len(rules.asns),
        }
        if report.get("aggregate_counts") != expected_report_counts:
            errors.append("update report aggregate counts do not match canonical rules")
        expected_registry_coverage = {}
        for name, version in (("ipv4", 4), ("ipv6", 6)):
            registered_addresses = sum(
                network.num_addresses
                for network in rules.registry_networks
                if network.version == version
            )
            expected_registry_coverage[name] = {
                "registered_addresses": registered_addresses,
                "missing_addresses": 0,
                "missing_ratio": 0.0,
            }
        if report.get("registry_coverage") != expected_registry_coverage:
            errors.append("registry coverage report does not match verified snapshots")
    for source in source_config["sources"]:
        metadata_path = root / "upstream" / "sources" / source["id"] / "metadata.json"
        if not metadata_path.exists():
            errors.append(f"missing source metadata for {source['id']}")
            continue
        source_metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        if source_metadata.get("project") != source["project"]:
            errors.append(f"source project mismatch for {source['id']}")
        if source_metadata.get("license") != source["license"]:
            errors.append(f"source license mismatch for {source['id']}")
        if source["kind"] == "rir-statistics":
            serial_date = source_metadata.get("serial_date", "")
            if len(serial_date) != 8 or not serial_date.isdigit():
                errors.append(f"invalid registry serial date for {source['id']}")
        digest = source_metadata.get("sha256", "")
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            errors.append(f"invalid source content hash for {source['id']}")
        for category in source.get("categories", [source.get("category")]):
            if not category:
                continue
            snapshot_path = root / "upstream" / "sources" / source["id"] / f"{category}.txt"
            if not snapshot_path.exists():
                errors.append(f"missing {category} snapshot for {source['id']}")
                continue
            count = len(read_values(snapshot_path))
            if source_metadata.get("counts", {}).get(category) != count:
                errors.append(f"source metadata count mismatch for {source['id']} {category}")

    lifecycle_path = root / "upstream" / "lifecycle.json"
    if not lifecycle_path.exists():
        errors.append("missing upstream/lifecycle.json")
    else:
        lifecycle = json.loads(lifecycle_path.read_text(encoding="utf-8"))
        if lifecycle.get("schema_version") != 3:
            errors.append("unsupported lifecycle schema version")
        if lifecycle.get("policy") != {
            "retire_after_successes": source_config["policy"]["retire_after_successes"],
            "max_retire_ratio": source_config["policy"]["max_retire_ratio"],
            "max_retire_count": source_config["policy"]["max_retire_count"],
        }:
            errors.append("lifecycle policy does not match source configuration")
    return errors


def _header(title: str) -> list[str]:
    return [
        "[Rule]",
        f"# {title}",
        "# AUTO-GENERATED by scripts/build.py; do not edit this file directly.",
        DATA_NOTICE,
        "# No LAN ranges. IPv6 retained. GEOSITE intentionally omitted.",
        "",
    ]


def _domain_policy_rules(
    exact_domains: tuple[str, ...],
    domain_suffixes: tuple[str, ...],
    domain_keywords: tuple[str, ...],
) -> list[str]:
    return [
        *(f"DOMAIN,{value},DIRECT" for value in exact_domains),
        *(f"DOMAIN-SUFFIX,{value},DIRECT" for value in domain_suffixes),
        *(f"DOMAIN-KEYWORD,{value},DIRECT" for value in domain_keywords),
    ]


def _domain_provider_rules(
    exact_domains: tuple[str, ...],
    domain_suffixes: tuple[str, ...],
    domain_keywords: tuple[str, ...],
) -> list[str]:
    return [
        *(f"DOMAIN,{value}" for value in exact_domains),
        *(f"DOMAIN-SUFFIX,{value}" for value in domain_suffixes),
        *(f"DOMAIN-KEYWORD,{value}" for value in domain_keywords),
    ]


def _ipv4_policy_rules(rules: RuleSet) -> list[str]:
    return [f"IP-CIDR,{network},DIRECT,no-resolve" for network in rules.ipv4]


def _ipv6_policy_rules(rules: RuleSet) -> list[str]:
    return [f"IP-CIDR6,{network},DIRECT,no-resolve" for network in rules.ipv6]


def render_outputs(rules: RuleSet) -> dict[str, str]:
    domain_rules = _domain_policy_rules(
        rules.exact_domains, rules.domain_suffixes, rules.domain_keywords
    )
    max_domain_rules = _domain_policy_rules(
        rules.max_exact_domains,
        rules.max_domain_suffixes,
        rules.max_domain_keywords,
    )
    domain_provider_rules = _domain_provider_rules(
        rules.exact_domains, rules.domain_suffixes, rules.domain_keywords
    )
    max_domain_provider_rules = _domain_provider_rules(
        rules.max_exact_domains,
        rules.max_domain_suffixes,
        rules.max_domain_keywords,
    )
    ipv4_rules = _ipv4_policy_rules(rules)
    ipv6_rules = _ipv6_policy_rules(rules)
    asn_rules = [f"IP-ASN,{asn},DIRECT" for asn in rules.asns]

    full_lines = [
        *_header("China mainland public-network direct rules"),
        "# Domains",
        *domain_rules,
        "",
        "# Public IPv4",
        *ipv4_rules,
        "",
        "# Public IPv6",
        *ipv6_rules,
        "",
        "# Major mainland autonomous systems",
        *asn_rules,
        "",
        "# GeoIP fallback",
        "GEOIP,CN,DIRECT",
        "",
    ]
    max_full_lines = [
        *_header("China mainland maximum-coverage public-network direct rules"),
        "# Domains (includes mainland-oriented IDN/TLD coverage)",
        *max_domain_rules,
        "",
        "# Public IPv4",
        *ipv4_rules,
        "",
        "# Public IPv6",
        *ipv6_rules,
        "",
        "# Major mainland autonomous systems",
        *asn_rules,
        "",
        "# GeoIP fallback",
        "GEOIP,CN,DIRECT",
        "",
    ]
    ip_lines = [
        *_header("China mainland public IP direct rules"),
        *ipv4_rules,
        *ipv6_rules,
        *asn_rules,
        "GEOIP,CN,DIRECT",
        "",
    ]
    domain_lines = [*_header("China mainland domain direct rules"), *domain_rules, ""]
    max_domain_lines = [
        *_header("China mainland maximum-coverage domain direct rules"),
        *max_domain_rules,
        "",
    ]
    ipv4_lines = [*_header("China mainland public IPv4 direct rules"), *ipv4_rules, ""]
    ipv6_lines = [*_header("China mainland public IPv6 direct rules"), *ipv6_rules, ""]

    ip_provider_rules = [
        *(f"IP-CIDR,{network},no-resolve" for network in rules.ipv4),
        *(f"IP-CIDR6,{network},no-resolve" for network in rules.ipv6),
        *(f"IP-ASN,{asn}" for asn in rules.asns),
        "GEOIP,CN",
    ]
    strict_provider = [*domain_provider_rules, *ip_provider_rules]
    max_provider = [*max_domain_provider_rules, *ip_provider_rules]
    clash_lines = [
        "# AUTO-GENERATED classical rule-provider for Clash/Mihomo/Stash.",
        DATA_NOTICE,
        "# Assign the provider to DIRECT in the client configuration.",
        "payload:",
        *(f"  - '{value}'" for value in strict_provider),
        "",
    ]
    clash_max_lines = [
        "# AUTO-GENERATED maximum-coverage classical provider for Clash/Mihomo/Stash.",
        DATA_NOTICE,
        "# Assign the provider to DIRECT in the client configuration.",
        "payload:",
        *(f"  - '{value}'" for value in max_provider),
        "",
    ]
    rule_set_lines = [
        "# AUTO-GENERATED policy-free remote rule set.",
        DATA_NOTICE,
        *strict_provider,
        "",
    ]
    max_rule_set_lines = [
        "# AUTO-GENERATED maximum-coverage policy-free remote rule set.",
        DATA_NOTICE,
        *max_provider,
        "",
    ]
    shadowrocket_module_lines = [
        "#!name=CN Direct Rules · Complete",
        "#!desc=中国大陆公网独立完整直连模块；自动更新，不含局域网规则。",
        "# Generated from https://github.com/GrandpaNiuu/cn-direct-rules",
        DATA_NOTICE,
        "",
        "[Rule]",
        *max_domain_rules,
        *ipv4_rules,
        *ipv6_rules,
        *asn_rules,
        "GEOIP,CN,DIRECT",
        "",
    ]
    shadowrocket_config_lines = [
        "# CN Direct Rules · Complete Configuration",
        "# AUTO-GENERATED by scripts/build.py; do not edit this file directly.",
        DATA_NOTICE,
        "# Importing this file replaces the current Shadowrocket configuration.",
        "",
        "[General]",
        "dns-server = system",
        "fallback-dns-server = system",
        "ipv6 = true",
        "prefer-ipv6 = false",
        "",
        "[Rule]",
        *max_domain_rules,
        *ipv4_rules,
        *ipv6_rules,
        *asn_rules,
        "GEOIP,CN,DIRECT",
        "FINAL,PROXY",
        "",
    ]

    outputs = {
        "cn.conf": "\n".join(full_lines),
        "cn-max.conf": "\n".join(max_full_lines),
        "cn-domain.conf": "\n".join(domain_lines),
        "cn-max-domain.conf": "\n".join(max_domain_lines),
        "cn-ip.conf": "\n".join(ip_lines),
        "cn-ipv4.conf": "\n".join(ipv4_lines),
        "cn-ipv6.conf": "\n".join(ipv6_lines),
        "clash/cn.yaml": "\n".join(clash_lines),
        "clash/cn-max.yaml": "\n".join(clash_max_lines),
        "rule-set/cn.list": "\n".join(rule_set_lines),
        "rule-set/cn-max.list": "\n".join(max_rule_set_lines),
        "shadowrocket/cn-direct.sgmodule": "\n".join(shadowrocket_module_lines),
        "shadowrocket/cn-direct.conf": "\n".join(shadowrocket_config_lines),
    }
    for operator, networks in sorted(rules.operator_networks.items()):
        operator_lines = [
            *_header(f"China mainland {operator} public IP direct rules"),
            *(
                f"IP-CIDR{'' if network.version == 4 else '6'},{network},DIRECT,no-resolve"
                for network in networks
            ),
            "",
        ]
        outputs[f"operators/{operator}.conf"] = "\n".join(operator_lines)
    registry_lines = [
        *_header("APNIC-registered mainland China public IP rules"),
        "# Registration country is not a guarantee of current physical location.",
        *(
            f"IP-CIDR{'' if network.version == 4 else '6'},{network},DIRECT,no-resolve"
            for network in rules.registry_networks
        ),
        "",
    ]
    outputs["registry/cn-allocated.conf"] = "\n".join(registry_lines)
    hashes = {
        name: hashlib.sha256(content.encode("utf-8")).hexdigest()
        for name, content in sorted(outputs.items())
    }
    manifest = {
        "schema_version": 1,
        "data_license": "https://github.com/GrandpaNiuu/cn-direct-rules/blob/main/DATA_LICENSE.md",
        "counts": {
            "asns": len(rules.asns),
            "domains": {
                "strict": {
                    "exact": len(rules.exact_domains),
                    "suffixes": len(rules.domain_suffixes),
                    "keywords": len(rules.domain_keywords),
                },
                "max": {
                    "exact": len(rules.max_exact_domains),
                    "suffixes": len(rules.max_domain_suffixes),
                    "keywords": len(rules.max_domain_keywords),
                },
            },
            "ipv4": len(rules.ipv4),
            "ipv6": len(rules.ipv6),
            "operators": {
                operator: len(networks)
                for operator, networks in sorted(rules.operator_networks.items())
            },
            "registry": {
                "ipv4": sum(network.version == 4 for network in rules.registry_networks),
                "ipv6": sum(network.version == 6 for network in rules.registry_networks),
            },
        },
        "files": hashes,
        "upstream": {
            "domains_sha256": rules.domain_source_sha256,
            "skipped_domain_regexes": rules.skipped_domain_regexes,
            "ipv4_sha256": hashlib.sha256(
                "\n".join(str(value) for value in rules.ipv4).encode("utf-8")
            ).hexdigest(),
            "ipv6_sha256": hashlib.sha256(
                "\n".join(str(value) for value in rules.ipv6).encode("utf-8")
            ).hexdigest(),
        },
    }
    outputs["manifest.json"] = json.dumps(
        manifest, ensure_ascii=False, indent=2, sort_keys=True
    ) + "\n"
    outputs["SHA256SUMS"] = "".join(
        f"{hashlib.sha256(content.encode('utf-8')).hexdigest()}  {name}\n"
        for name, content in sorted(outputs.items())
    )
    return outputs


def write_outputs(outputs: dict[str, str], output_dir: Path) -> None:
    for relative_name, content in outputs.items():
        destination = output_dir / relative_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        temporary.write_text(content, encoding="utf-8", newline="\n")
        temporary.replace(destination)
