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
    return RuleSet(
        exact_domains=read_values(root / "rules" / "exact-domains.txt"),
        domain_suffixes=read_values(root / "rules" / "domain-suffixes.txt"),
        domain_keywords=read_values(root / "rules" / "domain-keywords.txt"),
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
    errors.extend(_check_sorted_unique("exact domains", rules.exact_domains))
    errors.extend(_check_sorted_unique("domain suffixes", rules.domain_suffixes))
    errors.extend(_check_sorted_unique("domain keywords", rules.domain_keywords))
    errors.extend(_check_sorted_unique("ASNs", rules.asns, numeric=True))

    for name, values in (
        ("exact domain", rules.exact_domains),
        ("domain suffix", rules.domain_suffixes),
    ):
        errors.extend(
            error for value in values if (error := _check_domain(name, value)) is not None
        )

    if any(not keyword or "," in keyword or keyword != keyword.strip() for keyword in rules.domain_keywords):
        errors.append("domain keywords contain an empty, malformed, or whitespace-padded value")
    if any(asn <= 0 for asn in rules.asns):
        errors.append("ASNs must be positive integers")

    if rules.domain_suffixes.count("cn") != 1:
        errors.append("domain suffix 'cn' must appear exactly once")
    forbidden = set(read_values(root / "config" / "forbidden-domain-suffixes.txt"))
    unsafe = sorted(forbidden.intersection(rules.domain_suffixes))
    if unsafe:
        errors.append(f"unsafe global suffixes cannot be routed wholesale: {', '.join(unsafe)}")

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
    return errors


def _header(title: str) -> list[str]:
    return [
        "[Rule]",
        f"# {title}",
        "# AUTO-GENERATED by scripts/build.py; do not edit this file directly.",
        "# No LAN ranges. IPv6 retained. GEOSITE intentionally omitted.",
        "",
    ]


def _domain_policy_rules(rules: RuleSet) -> list[str]:
    return [
        *(f"DOMAIN,{value},DIRECT" for value in rules.exact_domains),
        *(f"DOMAIN-SUFFIX,{value},DIRECT" for value in rules.domain_suffixes),
        *(f"DOMAIN-KEYWORD,{value},DIRECT" for value in rules.domain_keywords),
    ]


def _ipv4_policy_rules(rules: RuleSet) -> list[str]:
    return [f"IP-CIDR,{network},DIRECT,no-resolve" for network in rules.ipv4]


def _ipv6_policy_rules(rules: RuleSet) -> list[str]:
    return [f"IP-CIDR6,{network},DIRECT,no-resolve" for network in rules.ipv6]


def render_outputs(rules: RuleSet) -> dict[str, str]:
    domain_rules = _domain_policy_rules(rules)
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
    ip_lines = [
        *_header("China mainland public IP direct rules"),
        *ipv4_rules,
        *ipv6_rules,
        *asn_rules,
        "GEOIP,CN,DIRECT",
        "",
    ]
    domain_lines = [*_header("China mainland domain direct rules"), *domain_rules, ""]
    ipv4_lines = [*_header("China mainland public IPv4 direct rules"), *ipv4_rules, ""]
    ipv6_lines = [*_header("China mainland public IPv6 direct rules"), *ipv6_rules, ""]

    clash_payload = [
        *(f"DOMAIN,{value}" for value in rules.exact_domains),
        *(f"DOMAIN-SUFFIX,{value}" for value in rules.domain_suffixes),
        *(f"DOMAIN-KEYWORD,{value}" for value in rules.domain_keywords),
        *(f"IP-CIDR,{network},no-resolve" for network in rules.ipv4),
        *(f"IP-CIDR6,{network},no-resolve" for network in rules.ipv6),
        *(f"IP-ASN,{asn}" for asn in rules.asns),
        "GEOIP,CN",
    ]
    clash_lines = [
        "# AUTO-GENERATED classical rule-provider for Clash/Mihomo/Stash.",
        "# Assign the provider to DIRECT in the client configuration.",
        "payload:",
        *(f"  - '{value}'" for value in clash_payload),
        "",
    ]

    outputs = {
        "cn.conf": "\n".join(full_lines),
        "cn-domain.conf": "\n".join(domain_lines),
        "cn-ip.conf": "\n".join(ip_lines),
        "cn-ipv4.conf": "\n".join(ipv4_lines),
        "cn-ipv6.conf": "\n".join(ipv6_lines),
        "clash/cn.yaml": "\n".join(clash_lines),
    }
    hashes = {
        name: hashlib.sha256(content.encode("utf-8")).hexdigest()
        for name, content in sorted(outputs.items())
    }
    manifest = {
        "schema_version": 1,
        "counts": {
            "asns": len(rules.asns),
            "domain_keywords": len(rules.domain_keywords),
            "domain_suffixes": len(rules.domain_suffixes),
            "exact_domains": len(rules.exact_domains),
            "ipv4": len(rules.ipv4),
            "ipv6": len(rules.ipv6),
        },
        "files": hashes,
        "upstream": {
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
    return outputs


def write_outputs(outputs: dict[str, str], output_dir: Path) -> None:
    for relative_name, content in outputs.items():
        destination = output_dir / relative_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        temporary.write_text(content, encoding="utf-8", newline="\n")
        temporary.replace(destination)
