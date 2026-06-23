from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable
from zoneinfo import ZoneInfo

from scripts.ruleset import ROOT, network_sort_key, read_values, validate_networks

_ASN_TOKEN = re.compile(r"^(?:AS)?(\d+)$", re.IGNORECASE)
_SPLIT_PATTERN = re.compile(r"[\s,|]+")


@dataclass(frozen=True)
class OriginRecord:
    prefix: str
    origins: tuple[int, ...]
    source: str


@dataclass(frozen=True)
class OriginAudit:
    main_prefixes: tuple[str, ...]
    rir_only_prefixes: tuple[str, ...]
    all_cn_prefixes: tuple[str, ...]
    main_asns_seen: tuple[int, ...]
    rir_only_asns_seen: tuple[int, ...]
    source_counts: dict[str, int]
    prefix_source_counts: dict[str, int]


def parse_origin_asns(value: str) -> tuple[int, ...]:
    """Parse one origin-AS field, including CAIDA-style multi-origin values.

    Examples: 4134, AS4134, 4134_4809, 4134,4809.
    """
    cleaned = value.strip().strip("{}[]()")
    if not cleaned:
        return ()
    origins: set[int] = set()
    for token in re.split(r"[_;,/]", cleaned):
        token = token.strip()
        if not token:
            continue
        match = _ASN_TOKEN.fullmatch(token)
        if match:
            asn = int(match.group(1))
            if asn > 0:
                origins.add(asn)
    return tuple(sorted(origins))


def _network_from_tokens(tokens: list[str]) -> tuple[ipaddress._BaseNetwork, int] | None:
    if not tokens:
        return None
    first = tokens[0]
    if "/" in first:
        try:
            return ipaddress.ip_network(first, strict=True), 1
        except ValueError:
            return None
    if len(tokens) >= 2 and tokens[1].isdigit():
        try:
            return ipaddress.ip_network(f"{first}/{tokens[1]}", strict=True), 2
        except ValueError:
            return None
    return None


def parse_origin_lines(text: str, *, source: str = "unknown") -> tuple[OriginRecord, ...]:
    """Parse normalized BGP prefix-origin text.

    Supported lines include:
    - 1.0.1.0/24 4134
    - 1.0.1.0 24 4134
    - 2400:3200::/32 AS4134
    - 1.0.1.0/24|4134_4809
    Comments beginning with # are ignored.
    """
    records: dict[str, set[int]] = {}
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        tokens = [token for token in _SPLIT_PATTERN.split(line) if token]
        parsed = _network_from_tokens(tokens)
        if parsed is None:
            continue
        network, consumed = parsed
        origins: set[int] = set()
        for token in tokens[consumed:]:
            origins.update(parse_origin_asns(token))
        if not origins or not network.is_global:
            continue
        records.setdefault(str(network), set()).update(origins)
    return tuple(
        OriginRecord(prefix, tuple(sorted(origins)), source)
        for prefix, origins in sorted(
            records.items(), key=lambda item: network_sort_key(ipaddress.ip_network(item[0]))
        )
    )


def collapse_prefixes(prefixes: Iterable[str], *, version: int) -> tuple[str, ...]:
    networks = [ipaddress.ip_network(prefix, strict=True) for prefix in prefixes]
    selected = [network for network in networks if network.version == version]
    collapsed = tuple(sorted(ipaddress.collapse_addresses(selected), key=network_sort_key))
    errors = validate_networks(collapsed, version)
    if errors:
        raise ValueError("; ".join(errors[:20]))
    return tuple(str(network) for network in collapsed)


def build_origin_audit(
    records: Iterable[OriginRecord],
    *,
    main_asns: Iterable[int],
    rir_asns: Iterable[int],
    min_sources: int = 1,
) -> OriginAudit:
    main = set(main_asns)
    rir = set(rir_asns)
    by_prefix: dict[str, set[int]] = {}
    source_by_prefix: dict[str, set[str]] = {}
    source_counts: dict[str, int] = {}

    for record in records:
        by_prefix.setdefault(record.prefix, set()).update(record.origins)
        source_by_prefix.setdefault(record.prefix, set()).add(record.source)
        source_counts[record.source] = source_counts.get(record.source, 0) + 1

    main_prefixes: set[str] = set()
    rir_only_prefixes: set[str] = set()
    main_asns_seen: set[int] = set()
    rir_only_asns_seen: set[int] = set()

    for prefix, origins in by_prefix.items():
        if len(source_by_prefix.get(prefix, set())) < min_sources:
            continue
        main_hits = origins & main
        rir_hits = origins & rir
        if main_hits:
            main_prefixes.add(prefix)
            main_asns_seen.update(main_hits)
        elif rir_hits:
            rir_only_prefixes.add(prefix)
            rir_only_asns_seen.update(rir_hits)

    all_cn = main_prefixes | rir_only_prefixes
    return OriginAudit(
        main_prefixes=_sort_prefixes(main_prefixes),
        rir_only_prefixes=_sort_prefixes(rir_only_prefixes),
        all_cn_prefixes=_sort_prefixes(all_cn),
        main_asns_seen=tuple(sorted(main_asns_seen)),
        rir_only_asns_seen=tuple(sorted(rir_only_asns_seen)),
        source_counts=dict(sorted(source_counts.items())),
        prefix_source_counts={
            prefix: len(sources)
            for prefix, sources in sorted(source_by_prefix.items(), key=lambda item: network_sort_key(ipaddress.ip_network(item[0])))
        },
    )


def _sort_prefixes(prefixes: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted(set(prefixes), key=lambda value: network_sort_key(ipaddress.ip_network(value))))


def render_outputs(audit: OriginAudit) -> dict[str, str]:
    main_lines = [
        "[Rule]",
        "# BGP origin audit: prefixes originated by high-confidence CN ASNs",
        "# AUTO-GENERATED by scripts/bgp_origin_audit.py; do not edit this file directly.",
        "# BGP observation is an audit signal and can include anycast or overseas-originated reachability.",
        "",
        *(rule_line(prefix) for prefix in audit.main_prefixes),
        "",
    ]
    rir_lines = [
        "[Rule]",
        "# BGP origin audit: prefixes originated only by RIR-registered CN ASNs",
        "# AUTO-GENERATED by scripts/bgp_origin_audit.py; do not edit this file directly.",
        "# These prefixes are audit-only and are not promoted into the main rule set.",
        "",
        *(rule_line(prefix) for prefix in audit.rir_only_prefixes),
        "",
    ]
    return {
        "dist/registry/cn-bgp-origin.conf": "\n".join(main_lines),
        "dist/registry/cn-bgp-rir-only-origin.conf": "\n".join(rir_lines),
    }


def rule_line(prefix: str) -> str:
    network = ipaddress.ip_network(prefix, strict=True)
    kind = "IP-CIDR" if network.version == 4 else "IP-CIDR6"
    return f"{kind},{network},DIRECT,no-resolve"


def manifest(audit: OriginAudit, outputs: dict[str, str], *, min_sources: int) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "generated_at": datetime.now(ZoneInfo("UTC")).replace(microsecond=0).isoformat(),
        "min_sources": min_sources,
        "counts": {
            "main_prefixes": len(audit.main_prefixes),
            "rir_only_prefixes": len(audit.rir_only_prefixes),
            "all_cn_prefixes": len(audit.all_cn_prefixes),
            "main_asns_seen": len(audit.main_asns_seen),
            "rir_only_asns_seen": len(audit.rir_only_asns_seen),
        },
        "source_counts": audit.source_counts,
        "files": {
            name: hashlib.sha256(content.encode("utf-8")).hexdigest()
            for name, content in sorted(outputs.items())
        },
    }


def read_origin_records(raw_dir: Path) -> tuple[OriginRecord, ...]:
    records: list[OriginRecord] = []
    for path in sorted(raw_dir.glob("*.txt")):
        records.extend(parse_origin_lines(path.read_text(encoding="utf-8", errors="replace"), source=path.stem))
    return tuple(records)


def write_outputs(root: Path, audit: OriginAudit, *, min_sources: int) -> list[Path]:
    outputs = render_outputs(audit)
    audit_manifest = manifest(audit, outputs, min_sources=min_sources)
    generated: dict[Path, str] = {
        root / "upstream" / "bgp-origin" / "prefixes-main-asn.txt": values_text(audit.main_prefixes),
        root / "upstream" / "bgp-origin" / "prefixes-rir-only-asn.txt": values_text(audit.rir_only_prefixes),
        root / "upstream" / "bgp-origin" / "asns-main-seen.txt": values_text(audit.main_asns_seen),
        root / "upstream" / "bgp-origin" / "asns-rir-only-seen.txt": values_text(audit.rir_only_asns_seen),
        root / "upstream" / "audit" / "bgp-origin-summary.json": json.dumps(audit_manifest, indent=2, sort_keys=True) + "\n",
        root / "dist" / "bgp-origin-audit-manifest.json": json.dumps(audit_manifest, indent=2, sort_keys=True) + "\n",
    }
    generated.update({root / relative_name: content for relative_name, content in outputs.items()})

    changed: list[Path] = []
    for path, content in generated.items():
        if path.exists() and path.read_text(encoding="utf-8") == content:
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
        changed.append(path)
    return changed


def values_text(values: Iterable[str | int]) -> str:
    materialized = [str(value) for value in values]
    return "\n".join(materialized) + ("\n" if materialized else "")


def load_asns(path: Path) -> tuple[int, ...]:
    if not path.exists():
        return ()
    return tuple(sorted(int(value) for value in read_values(path)))


def main() -> None:
    parser = argparse.ArgumentParser(description="Build normalized BGP origin audit outputs")
    parser.add_argument("--raw-dir", type=Path, default=ROOT / "upstream" / "bgp-origin" / "raw")
    parser.add_argument("--min-sources", type=int, default=1)
    args = parser.parse_args()

    if args.min_sources <= 0:
        raise ValueError("--min-sources must be positive")
    records = read_origin_records(args.raw_dir)
    if not records:
        raise FileNotFoundError(f"no normalized BGP origin .txt files found in {args.raw_dir}")
    audit = build_origin_audit(
        records,
        main_asns=load_asns(ROOT / "upstream" / "asns.txt"),
        rir_asns=load_asns(ROOT / "upstream" / "rir-global" / "asns.txt"),
        min_sources=args.min_sources,
    )
    changed = write_outputs(ROOT, audit, min_sources=args.min_sources)
    if changed:
        print("Updated BGP origin audit: " + ", ".join(str(path.relative_to(ROOT)) for path in changed))
    else:
        print("BGP origin audit outputs are already current")


if __name__ == "__main__":
    main()
