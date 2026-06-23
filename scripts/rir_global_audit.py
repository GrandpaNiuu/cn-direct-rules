from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable
from zoneinfo import ZoneInfo

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.ruleset import ROOT, network_sort_key, read_values, validate_networks


ACCEPTED_STATUSES = {"allocated", "assigned"}
RIR_IDS = ("apnic", "arin", "ripencc", "lacnic", "afrinic")


@dataclass(frozen=True)
class RirSnapshot:
    registry: str
    serial_date: str
    ipv4: tuple[str, ...]
    ipv6: tuple[str, ...]
    asns: tuple[int, ...]

    @property
    def total(self) -> int:
        return len(self.ipv4) + len(self.ipv6) + len(self.asns)


@dataclass(frozen=True)
class AuditResult:
    snapshots: tuple[RirSnapshot, ...]
    ipv4: tuple[str, ...]
    ipv6: tuple[str, ...]
    asns: tuple[int, ...]


def parse_delegated(
    text: str,
    *,
    registry: str,
    country: str = "CN",
    statuses: set[str] = ACCEPTED_STATUSES,
) -> RirSnapshot:
    """Parse one RIR delegated/extended statistics file for one country code.

    This is a registration-scope audit parser. The country code in delegated
    statistics is not treated as proof of current geographic routing location.
    """

    registry_id = registry.lower()
    country_code = country.upper()
    accepted_statuses = {status.lower() for status in statuses}

    serial_date = ""
    ipv4: list[ipaddress.IPv4Network] = []
    ipv6: list[ipaddress.IPv6Network] = []
    asns: set[int] = set()

    for raw_line in text.splitlines():
        line = raw_line.strip().lstrip("\ufeff")
        if not line or line.startswith("#"):
            continue
        fields = [field.strip() for field in line.split("|")]
        if len(fields) >= 3 and fields[0] == "2" and fields[1].lower() == registry_id:
            candidate = fields[2]
            if len(candidate) == 8 and candidate.isdigit():
                serial_date = candidate
            continue
        if (
            len(fields) < 7
            or fields[0].lower() != registry_id
            or fields[1].upper() != country_code
            or fields[2].lower() not in {"ipv4", "ipv6", "asn"}
            or fields[6].lower() not in accepted_statuses
        ):
            continue

        resource_type, start_value, count_value = fields[2].lower(), fields[3], fields[4]
        if resource_type == "ipv4":
            start = ipaddress.IPv4Address(start_value)
            count = int(count_value)
            if count <= 0 or int(start) + count - 1 > 2**32 - 1:
                raise ValueError(f"invalid {registry} IPv4 allocation: {raw_line}")
            end = ipaddress.IPv4Address(int(start) + count - 1)
            ipv4.extend(ipaddress.summarize_address_range(start, end))
        elif resource_type == "ipv6":
            prefix = int(count_value)
            if not 0 <= prefix <= 128:
                raise ValueError(f"invalid {registry} IPv6 prefix length: {raw_line}")
            ipv6.append(ipaddress.ip_network(f"{start_value}/{prefix}", strict=True))
        else:
            start_asn = int(start_value)
            count = int(count_value)
            if count <= 0 or start_asn <= 0 or start_asn + count - 1 > 4_294_967_296:
                raise ValueError(f"invalid {registry} ASN allocation: {raw_line}")
            asns.update(range(start_asn, start_asn + count))

    if len(serial_date) != 8 or not serial_date.isdigit():
        if ipv4 or ipv6 or asns:
            serial_date = "unknown"
        else:
            preview = "\n".join(text.splitlines()[:5])[:500]
            raise ValueError(
                f"{registry} delegated statistics file has no valid serial date or CN resources; "
                f"first lines: {preview!r}"
            )

    collapsed4 = tuple(sorted(ipaddress.collapse_addresses(ipv4), key=network_sort_key))
    collapsed6 = tuple(sorted(ipaddress.collapse_addresses(ipv6), key=network_sort_key))
    errors = [*validate_networks(collapsed4, 4), *validate_networks(collapsed6, 6)]
    if errors:
        raise ValueError("; ".join(errors[:20]))

    return RirSnapshot(
        registry=registry,
        serial_date=serial_date,
        ipv4=tuple(str(network) for network in collapsed4),
        ipv6=tuple(str(network) for network in collapsed6),
        asns=tuple(sorted(asns)),
    )


def combine_snapshots(snapshots: Iterable[RirSnapshot]) -> AuditResult:
    materialized = tuple(snapshots)
    ipv4 = tuple(
        sorted(
            ipaddress.collapse_addresses(
                ipaddress.ip_network(value, strict=True)
                for snapshot in materialized
                for value in snapshot.ipv4
            ),
            key=network_sort_key,
        )
    )
    ipv6 = tuple(
        sorted(
            ipaddress.collapse_addresses(
                ipaddress.ip_network(value, strict=True)
                for snapshot in materialized
                for value in snapshot.ipv6
            ),
            key=network_sort_key,
        )
    )
    return AuditResult(
        snapshots=materialized,
        ipv4=tuple(str(network) for network in ipv4),
        ipv6=tuple(str(network) for network in ipv6),
        asns=tuple(sorted({asn for snapshot in materialized for asn in snapshot.asns})),
    )


def asn_diff(main_asns: Iterable[int], rir_asns: Iterable[int]) -> dict[str, Any]:
    main = set(main_asns)
    rir = set(rir_asns)
    intersection = main & rir
    return {
        "counts": {
            "main": len(main),
            "rir": len(rir),
            "intersection": len(intersection),
            "only_in_main": len(main - rir),
            "only_in_rir": len(rir - main),
        },
        "only_in_main": sorted(main - rir),
        "only_in_rir": sorted(rir - main),
    }


def _policy_header(title: str) -> list[str]:
    return [
        "[Rule]",
        f"# {title}",
        "# AUTO-GENERATED by scripts/rir_global_audit.py; do not edit this file directly.",
        "# Registration country is an audit signal, not a guarantee of current physical location.",
        "",
    ]


def render_outputs(audit: AuditResult) -> dict[str, str]:
    ip_lines = [
        *_policy_header("Global RIR CN registered public IP audit rules"),
        "# Public IPv4 registered with country code CN across the five RIRs",
        *(f"IP-CIDR,{network},DIRECT,no-resolve" for network in audit.ipv4),
        "",
        "# Public IPv6 registered with country code CN across the five RIRs",
        *(f"IP-CIDR6,{network},DIRECT,no-resolve" for network in audit.ipv6),
        "",
    ]
    asn_lines = [
        *_policy_header("Global RIR CN registered ASN audit rules"),
        "# ASNs registered with country code CN across the five RIRs",
        *(f"IP-ASN,{asn},DIRECT" for asn in audit.asns),
        "",
    ]
    return {
        "dist/registry/cn-global-allocated.conf": "\n".join(ip_lines),
        "dist/registry/cn-rir-asn.conf": "\n".join(asn_lines),
    }


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def _values_text(values: Iterable[str | int]) -> str:
    materialized = [str(value) for value in values]
    return "\n".join(materialized) + ("\n" if materialized else "")


def load_audit(raw_dir: Path, *, country: str) -> AuditResult:
    snapshots = []
    for registry in RIR_IDS:
        path = raw_dir / f"{registry}.txt"
        if not path.exists():
            raise FileNotFoundError(f"missing raw RIR delegated file: {path}")
        snapshots.append(
            parse_delegated(
                path.read_text(encoding="utf-8", errors="replace"),
                registry=registry,
                country=country,
            )
        )
    return combine_snapshots(snapshots)


def manifest(audit: AuditResult, outputs: dict[str, str], diff: dict[str, Any], *, country: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "generated_at": datetime.now(ZoneInfo("UTC")).replace(microsecond=0).isoformat(),
        "country": country,
        "counts": {"ipv4": len(audit.ipv4), "ipv6": len(audit.ipv6), "asns": len(audit.asns)},
        "asn_diff_counts": diff["counts"],
        "sources": {
            snapshot.registry: {
                "serial_date": snapshot.serial_date,
                "counts": {"ipv4": len(snapshot.ipv4), "ipv6": len(snapshot.ipv6), "asns": len(snapshot.asns)},
            }
            for snapshot in audit.snapshots
        },
        "files": {
            name: hashlib.sha256(content.encode("utf-8")).hexdigest()
            for name, content in sorted(outputs.items())
        },
    }


def write_outputs(root: Path, audit: AuditResult, *, country: str) -> list[Path]:
    outputs = render_outputs(audit)
    main_asns_path = root / "upstream" / "asns.txt"
    main_asns = [int(value) for value in read_values(main_asns_path)] if main_asns_path.exists() else []
    diff = asn_diff(main_asns, audit.asns)
    audit_manifest = manifest(audit, outputs, diff, country=country)

    generated: dict[Path, str] = {
        root / "upstream" / "rir-global" / "ipv4.txt": _values_text(audit.ipv4),
        root / "upstream" / "rir-global" / "ipv6.txt": _values_text(audit.ipv6),
        root / "upstream" / "rir-global" / "asns.txt": _values_text(audit.asns),
        root / "upstream" / "audit" / "asn-diff.json": json.dumps(diff, indent=2, sort_keys=True) + "\n",
        root / "upstream" / "audit" / "rir-cn-summary.json": json.dumps(audit_manifest, indent=2, sort_keys=True) + "\n",
        root / "dist" / "rir-audit-manifest.json": json.dumps(audit_manifest, indent=2, sort_keys=True) + "\n",
    }
    generated.update({root / relative_name: content for relative_name, content in outputs.items()})
    for snapshot in audit.snapshots:
        prefix = root / "upstream" / "rir-global" / "sources" / snapshot.registry
        generated[prefix / "ipv4.txt"] = _values_text(snapshot.ipv4)
        generated[prefix / "ipv6.txt"] = _values_text(snapshot.ipv6)
        generated[prefix / "asns.txt"] = _values_text(snapshot.asns)

    changed: list[Path] = []
    for path, content in generated.items():
        if path.exists() and path.read_text(encoding="utf-8") == content:
            continue
        _write(path, content)
        changed.append(path)
    return changed


def main() -> None:
    parser = argparse.ArgumentParser(description="Build global RIR CN registration audit outputs")
    parser.add_argument("--country", default="CN", help="ISO 3166 alpha-2 country code")
    parser.add_argument("--raw-dir", type=Path, default=ROOT / "upstream" / "rir-global" / "raw")
    args = parser.parse_args()

    country = args.country.upper()
    audit = load_audit(args.raw_dir, country=country)
    changed = write_outputs(ROOT, audit, country=country)
    if changed:
        print("Updated RIR audit: " + ", ".join(str(path.relative_to(ROOT)) for path in changed))
    else:
        print("RIR audit outputs are already current")


if __name__ == "__main__":
    main()
