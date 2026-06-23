from __future__ import annotations

import gzip
import hashlib
import ipaddress
import json
import re
import sys
import time
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable
from zoneinfo import ZoneInfo

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.ruleset import ROOT, network_sort_key, read_values, validate_networks

USER_AGENT = "GrandpaNiuu/cn-direct-rules BGP origin audit"
ASN_TOKEN = re.compile(r"^(?:AS)?(\d+)$", re.IGNORECASE)


@dataclass(frozen=True)
class OriginRecord:
    prefix: str
    origins: tuple[int, ...]


@dataclass(frozen=True)
class BgpAudit:
    main_prefixes: tuple[str, ...]
    rir_only_prefixes: tuple[str, ...]
    main_asns_seen: tuple[int, ...]
    rir_only_asns_seen: tuple[int, ...]
    source_url: str
    sha256: str
    records_seen: int


def candidate_urls(now: datetime | None = None) -> list[str]:
    current = now or datetime.now(ZoneInfo("UTC"))
    urls: list[str] = []
    for offset in range(0, 10):
        day = current - timedelta(days=offset)
        year = day.strftime("%Y")
        month = day.strftime("%m")
        stamp = day.strftime("%Y%m%d")
        for hour in ("1200", "0000", "0800", "1600", "2000"):
            urls.append(
                "https://publicdata.caida.org/datasets/routing/routeviews-prefix2as/"
                f"{year}/{month}/routeviews-rv2-{stamp}-{hour}.pfx2as.gz"
            )
    return urls


def download_first(urls: Iterable[str], *, max_bytes: int = 120_000_000) -> tuple[bytes, str, str]:
    failures: list[str] = []
    for url in urls:
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(request, timeout=90) as response:
                chunks: list[bytes] = []
                total = 0
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > max_bytes:
                        raise ValueError(f"download exceeds {max_bytes} bytes")
                    chunks.append(chunk)
            payload = b"".join(chunks)
            return payload, url, hashlib.sha256(payload).hexdigest()
        except Exception as error:
            failures.append(f"{url}: {error}")
            time.sleep(0.2)
    raise RuntimeError("no BGP origin snapshot could be downloaded: " + "; ".join(failures[-5:]))


def parse_origin_asns(value: str) -> tuple[int, ...]:
    origins: set[int] = set()
    for token in re.split(r"[_;,/]", value.strip().strip("{}[]()")):
        token = token.strip()
        if not token:
            continue
        match = ASN_TOKEN.fullmatch(token)
        if match:
            asn = int(match.group(1))
            if asn > 0:
                origins.add(asn)
    return tuple(sorted(origins))


def parse_pfx2as(payload: bytes) -> tuple[OriginRecord, ...]:
    text = gzip.decompress(payload).decode("utf-8", errors="replace")
    records: dict[str, set[int]] = {}
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = re.split(r"\s+", line)
        if len(parts) < 3:
            continue
        try:
            network = ipaddress.ip_network(f"{parts[0]}/{parts[1]}", strict=True)
        except ValueError:
            continue
        if not network.is_global:
            continue
        origins = parse_origin_asns(parts[2])
        if not origins:
            continue
        records.setdefault(str(network), set()).update(origins)
    return tuple(
        OriginRecord(prefix, tuple(sorted(origins)))
        for prefix, origins in sorted(records.items(), key=lambda item: network_sort_key(ipaddress.ip_network(item[0])))
    )


def read_ints(path: Path) -> tuple[int, ...]:
    if not path.exists():
        return ()
    return tuple(sorted(int(value) for value in read_values(path)))


def build_audit(records: Iterable[OriginRecord], *, main_asns: Iterable[int], rir_asns: Iterable[int], source_url: str, sha256: str) -> BgpAudit:
    main = set(main_asns)
    rir = set(rir_asns)
    main_prefixes: set[str] = set()
    rir_only_prefixes: set[str] = set()
    main_seen: set[int] = set()
    rir_seen: set[int] = set()
    total = 0
    for record in records:
        total += 1
        origins = set(record.origins)
        main_hits = origins & main
        rir_hits = origins & rir
        if main_hits:
            main_prefixes.add(record.prefix)
            main_seen.update(main_hits)
        elif rir_hits:
            rir_only_prefixes.add(record.prefix)
            rir_seen.update(rir_hits)
    main_sorted = sort_prefixes(main_prefixes)
    rir_sorted = sort_prefixes(rir_only_prefixes)
    validate_prefixes(main_sorted)
    validate_prefixes(rir_sorted)
    return BgpAudit(
        main_prefixes=main_sorted,
        rir_only_prefixes=rir_sorted,
        main_asns_seen=tuple(sorted(main_seen)),
        rir_only_asns_seen=tuple(sorted(rir_seen)),
        source_url=source_url,
        sha256=sha256,
        records_seen=total,
    )


def sort_prefixes(prefixes: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted(set(prefixes), key=lambda value: network_sort_key(ipaddress.ip_network(value))))


def validate_prefixes(prefixes: Iterable[str]) -> None:
    networks = tuple(ipaddress.ip_network(prefix, strict=True) for prefix in prefixes)
    ipv4 = tuple(network for network in networks if network.version == 4)
    ipv6 = tuple(network for network in networks if network.version == 6)
    errors = [*validate_networks(ipv4, 4), *validate_networks(ipv6, 6)]
    if errors:
        raise ValueError("; ".join(errors[:20]))


def values_text(values: Iterable[str | int]) -> str:
    materialized = [str(value) for value in values]
    return "\n".join(materialized) + ("\n" if materialized else "")


def write_if_changed(path: Path, content: str) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text(encoding="utf-8") == content:
        return False
    path.write_text(content, encoding="utf-8", newline="\n")
    return True


def run() -> list[Path]:
    changed: list[Path] = []
    generated_at = datetime.now(ZoneInfo("UTC")).replace(microsecond=0).isoformat()
    main_asns = read_ints(ROOT / "upstream" / "asns.txt")
    rir_asns = read_ints(ROOT / "upstream" / "rir-global" / "asns.txt")
    try:
        payload, source_url, sha256 = download_first(candidate_urls())
        records = parse_pfx2as(payload)
        audit = build_audit(records, main_asns=main_asns, rir_asns=rir_asns, source_url=source_url, sha256=sha256)
        summary: dict[str, Any] = {
            "schema_version": 1,
            "generated_at": generated_at,
            "mode": "fully-automated-bgp-origin-audit",
            "source_url": audit.source_url,
            "source_sha256": audit.sha256,
            "records_seen": audit.records_seen,
            "counts": {
                "main_prefixes": len(audit.main_prefixes),
                "rir_only_prefixes": len(audit.rir_only_prefixes),
                "main_asns_seen": len(audit.main_asns_seen),
                "rir_only_asns_seen": len(audit.rir_only_asns_seen),
            },
            "promotion_policy": {
                "strict_rules": "main source pipeline only",
                "bgp_origin_outputs": "automatic audit only",
                "human_review_required": False,
            },
        }
        files = {
            ROOT / "upstream" / "bgp-origin" / "prefixes-main-asn.txt": values_text(audit.main_prefixes),
            ROOT / "upstream" / "bgp-origin" / "prefixes-rir-only-asn.txt": values_text(audit.rir_only_prefixes),
            ROOT / "upstream" / "bgp-origin" / "asns-main-seen.txt": values_text(audit.main_asns_seen),
            ROOT / "upstream" / "bgp-origin" / "asns-rir-only-seen.txt": values_text(audit.rir_only_asns_seen),
            ROOT / "upstream" / "audit" / "bgp-origin-summary.json": json.dumps(summary, indent=2, sort_keys=True) + "\n",
        }
    except Exception as error:
        files = {
            ROOT / "upstream" / "audit" / "bgp-origin-status.json": json.dumps(
                {
                    "schema_version": 1,
                    "generated_at": generated_at,
                    "mode": "fully-automated-bgp-origin-audit",
                    "refreshed": False,
                    "error": str(error),
                    "action": "kept previous BGP audit snapshots",
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        }
    for path, content in files.items():
        if write_if_changed(path, content):
            changed.append(path)
    return changed


def main() -> None:
    changed = run()
    if changed:
        print("BGP origin audit updated: " + ", ".join(str(path.relative_to(ROOT)) for path in changed))
    else:
        print("BGP origin audit outputs are unchanged")


if __name__ == "__main__":
    main()
