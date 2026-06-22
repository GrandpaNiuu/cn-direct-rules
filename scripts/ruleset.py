from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]


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


def read_values(path: Path) -> tuple[str, ...]:
    return tuple(
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


def load_rules(root: Path = ROOT) -> RuleSet:
    manual_exact = read_values(root / "rules" / "exact-domains.txt")
    manual_suffixes = read_values(root / "rules" / "domain-suffixes.txt")
    manual_keywords = read_values(root / "rules" / "domain-keywords.txt")
    upstream_exact = read_values(root / "upstream" / "domain-exact.txt")
    upstream_suffixes = read_values(root / "upstream" / "domain-suffixes.txt")
    upstream_keywords = read_values(root / "upstream" / "domain-keywords.txt")
    domain_metadata = json.loads(
        (root / "upstream" / "domain-metadata.json").read_text(encoding="utf-8")
    )
    forbidden = set(read_values(root / "config" / "forbidden-domain-suffixes.txt"))

    max_exact = tuple(sorted(set(manual_exact + upstream_exact), key=str.casefold))
    max_suffixes = tuple(sorted(set(manual_suffixes + upstream_suffixes), key=str.casefold))
    max_keywords = tuple(sorted(set(manual_keywords + upstream_keywords), key=str.casefold))
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
        asns=tuple(int(value) for value in read_values(root / "rules" / "asns.txt")),
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
        ("manual exact domains", "rules/exact-domains.txt"),
        ("manual domain suffixes", "rules/domain-suffixes.txt"),
        ("manual domain keywords", "rules/domain-keywords.txt"),
        ("upstream exact domains", "upstream/domain-exact.txt"),
        ("upstream domain suffixes", "upstream/domain-suffixes.txt"),
        ("upstream domain keywords", "upstream/domain-keywords.txt"),
    ):
        errors.extend(_check_sorted_unique(label, read_values(root / relative_path)))

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
    if not set(rules.domain_suffixes).issubset(rules.max_domain_suffixes):
        errors.append("max domain suffixes must contain every strict suffix")

    errors.extend(validate_networks(rules.ipv4, 4))
    errors.extend(validate_networks(rules.ipv6, 6))

    source_config = json.loads((root / "config" / "sources.json").read_text(encoding="utf-8"))
    for name, values in (("ipv4", rules.ipv4), ("ipv6", rules.ipv6)):
        bounds = source_config[name]
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
    domain_bounds = source_config["domains"]
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
    return errors


def _header(title: str) -> list[str]:
    return [
        "[Rule]",
        f"# {title}",
        "# AUTO-GENERATED by scripts/build.py; do not edit this file directly.",
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
        "# Assign the provider to DIRECT in the client configuration.",
        "payload:",
        *(f"  - '{value}'" for value in strict_provider),
        "",
    ]
    clash_max_lines = [
        "# AUTO-GENERATED maximum-coverage classical provider for Clash/Mihomo/Stash.",
        "# Assign the provider to DIRECT in the client configuration.",
        "payload:",
        *(f"  - '{value}'" for value in max_provider),
        "",
    ]
    rule_set_lines = [
        "# AUTO-GENERATED policy-free remote rule set.",
        *strict_provider,
        "",
    ]
    max_rule_set_lines = [
        "# AUTO-GENERATED maximum-coverage policy-free remote rule set.",
        *max_provider,
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
    }
    hashes = {
        name: hashlib.sha256(content.encode("utf-8")).hexdigest()
        for name, content in sorted(outputs.items())
    }
    manifest = {
        "schema_version": 1,
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
