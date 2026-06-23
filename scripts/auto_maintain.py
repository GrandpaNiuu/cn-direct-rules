from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import sys
import time
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Any
from zoneinfo import ZoneInfo

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.ruleset import ROOT, network_sort_key, read_values, validate_networks

USER_AGENT = "GrandpaNiuu/cn-direct-rules auto maintainer"
ACCEPTED_STATUSES = {"allocated", "assigned"}
RIR_SOURCES: dict[str, list[str]] = {
    "apnic": [
        "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
        "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest",
    ],
    "arin": ["https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest"],
    "ripencc": ["https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest"],
    "lacnic": ["https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest"],
    "afrinic": ["https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest"],
}


@dataclass(frozen=True)
class RirSnapshot:
    registry: str
    serial_date: str
    ipv4: tuple[str, ...]
    ipv6: tuple[str, ...]
    asns: tuple[int, ...]
    source_url: str
    sha256: str


@dataclass(frozen=True)
class CombinedAudit:
    snapshots: tuple[RirSnapshot, ...]
    ipv4: tuple[str, ...]
    ipv6: tuple[str, ...]
    asns: tuple[int, ...]


def download(url: str, *, attempts: int = 3, max_bytes: int = 32_000_000) -> bytes:
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(request, timeout=60) as response:
                chunks: list[bytes] = []
                total = 0
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > max_bytes:
                        raise ValueError(f"download from {url} exceeds {max_bytes} bytes")
                    chunks.append(chunk)
                return b"".join(chunks)
        except Exception as error:
            last_error = error
            if attempt < attempts:
                time.sleep(2**attempt)
    raise RuntimeError(f"failed to download {url} after {attempts} attempts") from last_error


def download_first(urls: list[str]) -> tuple[bytes, str]:
    failures: list[str] = []
    for url in urls:
        try:
            return download(url), url
        except Exception as error:
            failures.append(f"{url}: {error}")
    raise RuntimeError("all mirrors failed: " + "; ".join(failures))


def parse_rir_delegated(text: str, *, registry: str, source_url: str, payload_sha256: str, country: str = "CN") -> RirSnapshot:
    registry_id = registry.lower()
    country_code = country.upper()
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
            if re.fullmatch(r"\d{8}", candidate):
                serial_date = candidate
            continue
        if len(fields) < 7:
            continue
        if fields[0].lower() != registry_id or fields[1].upper() != country_code:
            continue
        resource_type = fields[2].lower()
        status = fields[6].lower()
        if resource_type not in {"ipv4", "ipv6", "asn"} or status not in ACCEPTED_STATUSES:
            continue
        start_value = fields[3]
        count_value = fields[4]
        if resource_type == "ipv4":
            start = ipaddress.IPv4Address(start_value)
            count = int(count_value)
            if count <= 0 or int(start) + count - 1 > 2**32 - 1:
                raise ValueError(f"invalid IPv4 allocation from {registry}: {raw_line}")
            end = ipaddress.IPv4Address(int(start) + count - 1)
            ipv4.extend(ipaddress.summarize_address_range(start, end))
        elif resource_type == "ipv6":
            prefix = int(count_value)
            if not 0 <= prefix <= 128:
                raise ValueError(f"invalid IPv6 prefix from {registry}: {raw_line}")
            ipv6.append(ipaddress.ip_network(f"{start_value}/{prefix}", strict=True))
        else:
            start_asn = int(start_value)
            count = int(count_value)
            if count <= 0 or start_asn <= 0:
                raise ValueError(f"invalid ASN allocation from {registry}: {raw_line}")
            asns.update(range(start_asn, start_asn + count))

    if not serial_date:
        serial_date = "unknown"

    collapsed4 = tuple(sorted(ipaddress.collapse_addresses(ipv4), key=network_sort_key))
    collapsed6 = tuple(sorted(ipaddress.collapse_addresses(ipv6), key=network_sort_key))
    errors = [*validate_networks(collapsed4, 4), *validate_networks(collapsed6, 6)]
    if errors:
        raise ValueError("; ".join(errors[:20]))
    return RirSnapshot(
        registry=registry_id,
        serial_date=serial_date,
        ipv4=tuple(str(network) for network in collapsed4),
        ipv6=tuple(str(network) for network in collapsed6),
        asns=tuple(sorted(asns)),
        source_url=source_url,
        sha256=payload_sha256,
    )


def combine(snapshots: Iterable[RirSnapshot]) -> CombinedAudit:
    materialized = tuple(snapshots)
    ipv4_networks = [ipaddress.ip_network(value, strict=True) for snapshot in materialized for value in snapshot.ipv4]
    ipv6_networks = [ipaddress.ip_network(value, strict=True) for snapshot in materialized for value in snapshot.ipv6]
    ipv4 = tuple(sorted(ipaddress.collapse_addresses(ipv4_networks), key=network_sort_key))
    ipv6 = tuple(sorted(ipaddress.collapse_addresses(ipv6_networks), key=network_sort_key))
    return CombinedAudit(
        snapshots=materialized,
        ipv4=tuple(str(network) for network in ipv4),
        ipv6=tuple(str(network) for network in ipv6),
        asns=tuple(sorted({asn for snapshot in materialized for asn in snapshot.asns})),
    )


def read_ints(path: Path) -> tuple[int, ...]:
    if not path.exists():
        return ()
    return tuple(sorted(int(value) for value in read_values(path)))


def read_networks(path: Path) -> tuple[str, ...]:
    if not path.exists():
        return ()
    return tuple(read_values(path))


def address_coverage(routed: tuple[str, ...], registered: tuple[str, ...]) -> dict[str, Any]:
    if not registered:
        return {"registered_addresses": 0, "missing_addresses": 0, "missing_ratio": 0.0}
    routed_networks = [ipaddress.ip_network(value, strict=True) for value in routed]
    registered_networks = [ipaddress.ip_network(value, strict=True) for value in registered]
    registered_addresses = sum(network.num_addresses for network in ipaddress.collapse_addresses(registered_networks))
    routed_addresses = sum(network.num_addresses for network in ipaddress.collapse_addresses(routed_networks))
    union_addresses = sum(network.num_addresses for network in ipaddress.collapse_addresses([*routed_networks, *registered_networks]))
    missing_addresses = max(0, union_addresses - routed_addresses)
    return {
        "registered_addresses": registered_addresses,
        "missing_addresses": missing_addresses,
        "missing_ratio": missing_addresses / registered_addresses if registered_addresses else 0.0,
    }


def asn_diff(main_asns: tuple[int, ...], rir_asns: tuple[int, ...]) -> dict[str, Any]:
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


def text_values(values: Iterable[str | int]) -> str:
    materialized = [str(value) for value in values]
    return "\n".join(materialized) + ("\n" if materialized else "")


def write_if_changed(path: Path, content: str) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text(encoding="utf-8") == content:
        return False
    path.write_text(content, encoding="utf-8", newline="\n")
    return True


def build_markdown(summary: dict[str, Any]) -> str:
    counts = summary["counts"]
    coverage = summary["coverage"]
    failures = summary.get("failures", {})
    lines = [
        "# Automated coverage report",
        "",
        "This report is generated without manual review. High-risk data is kept in audit outputs unless it is already confirmed by the main source pipeline.",
        "",
        "## RIR CN registry audit",
        "",
        f"- RIR sources refreshed: {counts['sources_refreshed']}",
        f"- RIR sources failed: {counts['sources_failed']}",
        f"- Global RIR CN IPv4 networks: {counts['rir_ipv4']}",
        f"- Global RIR CN IPv6 networks: {counts['rir_ipv6']}",
        f"- Global RIR CN ASNs: {counts['rir_asns']}",
        "",
        "## Main-rule coverage against RIR registry",
        "",
        f"- IPv4 missing ratio: {coverage['ipv4']['missing_ratio']:.6f}",
        f"- IPv6 missing ratio: {coverage['ipv6']['missing_ratio']:.6f}",
        f"- ASN overlap: {summary['asn_diff']['counts']['intersection']} / {summary['asn_diff']['counts']['rir']}",
        "",
    ]
    if failures:
        lines.extend(["## Source failures", ""])
        for source, error in sorted(failures.items()):
            lines.append(f"- {source}: {error}")
        lines.append("")
    return "\n".join(lines)


def run() -> list[Path]:
    failures: dict[str, str] = {}
    snapshots: list[RirSnapshot] = []
    for registry, urls in RIR_SOURCES.items():
        try:
            payload, selected_url = download_first(urls)
            payload_hash = hashlib.sha256(payload).hexdigest()
            snapshots.append(
                parse_rir_delegated(
                    payload.decode("utf-8", errors="replace"),
                    registry=registry,
                    source_url=selected_url,
                    payload_sha256=payload_hash,
                )
            )
        except Exception as error:
            failures[registry] = str(error)

    changed: list[Path] = []
    generated_at = datetime.now(ZoneInfo("UTC")).replace(microsecond=0).isoformat()
    main_asns = read_ints(ROOT / "upstream" / "asns.txt")
    main_ipv4 = read_networks(ROOT / "upstream" / "ipv4.txt")
    main_ipv6 = read_networks(ROOT / "upstream" / "ipv6.txt")

    if snapshots:
        audit = combine(snapshots)
        diff = asn_diff(main_asns, audit.asns)
        coverage = {
            "ipv4": address_coverage(main_ipv4, audit.ipv4),
            "ipv6": address_coverage(main_ipv6, audit.ipv6),
        }
        summary: dict[str, Any] = {
            "schema_version": 1,
            "generated_at": generated_at,
            "mode": "fully-automated-audit",
            "promotion_policy": {
                "strict_rules": "main source pipeline only",
                "audit_outputs": "automatic",
                "human_review_required": False,
            },
            "counts": {
                "sources_refreshed": len(snapshots),
                "sources_failed": len(failures),
                "rir_ipv4": len(audit.ipv4),
                "rir_ipv6": len(audit.ipv6),
                "rir_asns": len(audit.asns),
                "main_ipv4": len(main_ipv4),
                "main_ipv6": len(main_ipv6),
                "main_asns": len(main_asns),
            },
            "coverage": coverage,
            "asn_diff": diff,
            "sources": {
                snapshot.registry: {
                    "serial_date": snapshot.serial_date,
                    "url": snapshot.source_url,
                    "sha256": snapshot.sha256,
                    "counts": {"ipv4": len(snapshot.ipv4), "ipv6": len(snapshot.ipv6), "asns": len(snapshot.asns)},
                }
                for snapshot in audit.snapshots
            },
            "failures": failures,
        }
        files = {
            ROOT / "upstream" / "rir-global" / "ipv4.txt": text_values(audit.ipv4),
            ROOT / "upstream" / "rir-global" / "ipv6.txt": text_values(audit.ipv6),
            ROOT / "upstream" / "rir-global" / "asns.txt": text_values(audit.asns),
            ROOT / "upstream" / "audit" / "asn-diff.json": json.dumps(diff, indent=2, sort_keys=True) + "\n",
            ROOT / "upstream" / "audit" / "coverage.json": json.dumps(summary, indent=2, sort_keys=True) + "\n",
            ROOT / "upstream" / "audit" / "coverage.md": build_markdown(summary) + "\n",
            ROOT / "upstream" / "audit" / "rir-cn-summary.json": json.dumps(summary, indent=2, sort_keys=True) + "\n",
        }
        for snapshot in audit.snapshots:
            base = ROOT / "upstream" / "rir-global" / "sources" / snapshot.registry
            files[base / "ipv4.txt"] = text_values(snapshot.ipv4)
            files[base / "ipv6.txt"] = text_values(snapshot.ipv6)
            files[base / "asns.txt"] = text_values(snapshot.asns)
        for path, content in files.items():
            if write_if_changed(path, content):
                changed.append(path)
    else:
        status = {
            "schema_version": 1,
            "generated_at": generated_at,
            "mode": "fully-automated-audit",
            "refreshed": False,
            "failures": failures,
            "action": "kept previous audit snapshots",
        }
        path = ROOT / "upstream" / "audit" / "auto-maintain-status.json"
        if write_if_changed(path, json.dumps(status, indent=2, sort_keys=True) + "\n"):
            changed.append(path)
    return changed


def main() -> None:
    changed = run()
    if changed:
        print("Automated audit updated: " + ", ".join(str(path.relative_to(ROOT)) for path in changed))
    else:
        print("Automated audit outputs are unchanged")


if __name__ == "__main__":
    main()
