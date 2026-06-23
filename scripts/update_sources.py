from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
import tarfile
import time
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Any
from zoneinfo import ZoneInfo

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.ruleset import ROOT, network_sort_key, read_values, validate_networks


USER_AGENT = "GrandpaNiuu/cn-direct-rules source updater"


@dataclass(frozen=True)
class DomainEntry:
    kind: str
    value: str
    attributes: frozenset[str]


@dataclass(frozen=True)
class DomainSnapshot:
    exact: tuple[str, ...]
    suffixes: tuple[str, ...]
    keywords: tuple[str, ...]
    skipped_regexes: int

    @property
    def total(self) -> int:
        return len(self.exact) + len(self.suffixes) + len(self.keywords)


@dataclass(frozen=True)
class RegistrySnapshot:
    serial_date: str
    ipv4: tuple[str, ...]
    ipv6: tuple[str, ...]

    @property
    def total(self) -> int:
        return len(self.ipv4) + len(self.ipv6)


@dataclass(frozen=True)
class RegistryCoverage:
    registered_addresses: int
    missing_addresses: int
    missing_ratio: float


def registry_coverage(
    routed: tuple[str, ...], registered: tuple[str, ...]
) -> RegistryCoverage:
    routed_networks = [ipaddress.ip_network(value, strict=True) for value in routed]
    registered_networks = [
        ipaddress.ip_network(value, strict=True) for value in registered
    ]
    registered_addresses = sum(
        network.num_addresses
        for network in ipaddress.collapse_addresses(registered_networks)
    )
    routed_addresses = sum(
        network.num_addresses for network in ipaddress.collapse_addresses(routed_networks)
    )
    union_addresses = sum(
        network.num_addresses
        for network in ipaddress.collapse_addresses(
            [*routed_networks, *registered_networks]
        )
    )
    missing_addresses = union_addresses - routed_addresses
    return RegistryCoverage(
        registered_addresses,
        missing_addresses,
        missing_addresses / registered_addresses if registered_addresses else 0.0,
    )


def parse_rir_allocations(text: str, country: str = "CN") -> RegistrySnapshot:
    serial_date = ""
    ipv4: list[ipaddress.IPv4Network] = []
    ipv6: list[ipaddress.IPv6Network] = []
    for raw_line in text.splitlines():
        fields = raw_line.strip().split("|")
        if len(fields) == 7 and fields[0] == "2" and fields[1] == "apnic":
            serial_date = fields[2]
            continue
        if (
            len(fields) != 7
            or fields[0] != "apnic"
            or fields[1] != country
            or fields[2] not in {"ipv4", "ipv6"}
            or fields[6] not in {"allocated", "assigned"}
        ):
            continue
        if fields[2] == "ipv4":
            start = ipaddress.IPv4Address(fields[3])
            count = int(fields[4])
            if count <= 0 or int(start) + count - 1 > 2**32 - 1:
                raise ValueError(f"invalid APNIC IPv4 allocation: {raw_line}")
            end = ipaddress.IPv4Address(int(start) + count - 1)
            ipv4.extend(ipaddress.summarize_address_range(start, end))
        else:
            ipv6.append(ipaddress.ip_network(f"{fields[3]}/{fields[4]}", strict=True))
    if not re.fullmatch(r"\d{8}", serial_date):
        raise ValueError("APNIC statistics header has no valid serial date")
    collapsed4 = tuple(sorted(ipaddress.collapse_addresses(ipv4), key=network_sort_key))
    collapsed6 = tuple(sorted(ipaddress.collapse_addresses(ipv6), key=network_sort_key))
    errors = [*validate_networks(collapsed4, 4), *validate_networks(collapsed6, 6)]
    if errors:
        raise ValueError("; ".join(errors[:20]))
    return RegistrySnapshot(
        serial_date,
        tuple(str(network) for network in collapsed4),
        tuple(str(network) for network in collapsed6),
    )


@dataclass(frozen=True)
class LifecyclePolicy:
    retire_after_successes: int = 3
    max_retire_ratio: float = 0.01
    max_retire_count: int = 1000


@dataclass(frozen=True)
class ReconcileResult:
    values: tuple[str, ...]
    missing_counts: dict[str, int]
    added: tuple[str, ...]
    retired: tuple[str, ...]


@dataclass(frozen=True)
class DomainRepairResult:
    exact: tuple[str, ...]
    suffixes: tuple[str, ...]
    missing_counts: dict[str, dict[str, int]]


def _has_covering_suffix(value: str, suffixes: set[str], *, include_self: bool) -> bool:
    labels = value.split(".")
    start = 0 if include_self else 1
    return any(".".join(labels[index:]) in suffixes for index in range(start, len(labels)))


def _matches_domain_suffix(value: str, suffixes: set[str]) -> bool:
    return any(value == suffix or value.endswith("." + suffix) for suffix in suffixes)


def remove_high_risk_domain_rules(
    exact: tuple[str, ...],
    suffixes: tuple[str, ...],
    high_risk_suffixes: set[str],
    missing_counts: dict[str, dict[str, int]],
) -> DomainRepairResult:
    safe_exact = tuple(
        sorted(
            (value for value in set(exact) if not _matches_domain_suffix(value, high_risk_suffixes)),
            key=str.casefold,
        )
    )
    safe_suffixes = tuple(
        sorted(
            (
                value
                for value in set(suffixes)
                if not _matches_domain_suffix(value, high_risk_suffixes)
            ),
            key=str.casefold,
        )
    )
    return DomainRepairResult(
        safe_exact,
        safe_suffixes,
        {
            "domain-exact": {
                value: count
                for value, count in missing_counts.get("domain-exact", {}).items()
                if value in safe_exact
            },
            "domain-suffixes": {
                value: count
                for value, count in missing_counts.get("domain-suffixes", {}).items()
                if value in safe_suffixes
            },
        },
    )


def repair_domain_redundancy(
    exact: tuple[str, ...],
    suffixes: tuple[str, ...],
    missing_counts: dict[str, dict[str, int]],
) -> DomainRepairResult:
    suffix_set = set(suffixes)
    repaired_suffixes = tuple(
        sorted(
            (
                value
                for value in suffix_set
                if not _has_covering_suffix(value, suffix_set, include_self=False)
            ),
            key=str.casefold,
        )
    )
    repaired_suffix_set = set(repaired_suffixes)
    repaired_exact = tuple(
        sorted(
            (
                value
                for value in set(exact)
                if not _has_covering_suffix(value, repaired_suffix_set, include_self=True)
            ),
            key=str.casefold,
        )
    )
    return DomainRepairResult(
        repaired_exact,
        repaired_suffixes,
        {
            "domain-exact": {
                value: count
                for value, count in missing_counts.get("domain-exact", {}).items()
                if value in repaired_exact
            },
            "domain-suffixes": {
                value: count
                for value, count in missing_counts.get("domain-suffixes", {}).items()
                if value in repaired_suffixes
            },
        },
    )


def reconcile_values(
    previous: tuple[str, ...],
    observed: tuple[str, ...],
    missing_counts: dict[str, int],
    policy: LifecyclePolicy,
    advance_missing: bool = True,
) -> ReconcileResult:
    """Merge one validated observation while delaying and limiting removals."""
    previous_set = set(previous)
    observed_set = set(observed)
    next_missing: dict[str, int] = {}
    retained = set(observed_set)
    retired: list[str] = []
    for value in previous_set - observed_set:
        misses = missing_counts.get(value, 0) + (1 if advance_missing else 0)
        if misses >= policy.retire_after_successes:
            retired.append(value)
        else:
            next_missing[value] = misses
            retained.add(value)

    retirement_ratio = len(retired) / len(previous_set) if previous_set else 0.0
    if retired and (
        retirement_ratio > policy.max_retire_ratio
        or len(retired) > policy.max_retire_count
    ):
        raise ValueError(
            "retirement circuit breaker: "
            f"{len(retired)} rules ({retirement_ratio:.2%}) would be removed"
        )
    return ReconcileResult(
        values=tuple(sorted(retained, key=str.casefold)),
        missing_counts=dict(sorted(next_missing.items(), key=lambda item: item[0].casefold())),
        added=tuple(sorted(observed_set - previous_set, key=str.casefold)),
        retired=tuple(sorted(retired, key=str.casefold)),
    )


def can_advance_category(
    sources: list[dict[str, Any]],
    statuses: dict[str, str],
    category: str,
    previous_day: str | None,
    observation_day: str,
) -> bool:
    if previous_day == observation_day:
        return False
    relevant_source_ids = {
        source["id"]
        for source in sources
        if source.get("contributes_to_aggregate", True) is not False
        and category in source.get("categories", [source.get("category")])
    }
    return bool(relevant_source_ids) and all(
        statuses.get(source_id) == "refreshed" for source_id in relevant_source_ids
    )


_DNSMASQ_DOMAIN = re.compile(r"^server=/([^/]+)/[^/]+$")
_ASN_RULE = re.compile(r"^IP-ASN,(\d+)(?:\s*//.*)?$")


def parse_dnsmasq_domains(text: str) -> tuple[str, ...]:
    values: set[str] = set()
    for raw_line in text.splitlines():
        match = _DNSMASQ_DOMAIN.fullmatch(raw_line.strip())
        if match:
            values.add(match.group(1).lower())
    return tuple(sorted(values, key=str.casefold))


def parse_asn_list(text: str) -> tuple[int, ...]:
    values: set[int] = set()
    for raw_line in text.splitlines():
        match = _ASN_RULE.fullmatch(raw_line.strip())
        if match:
            values.add(int(match.group(1)))
    return tuple(sorted(values))


def download(url: str, attempts: int = 3, max_bytes: int = 32_000_000) -> bytes:
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
        except Exception as error:  # network failures vary by runner and provider
            last_error = error
            if attempt < attempts:
                time.sleep(2**attempt)
    raise RuntimeError(f"failed to download {url} after {attempts} attempts") from last_error


def download_first(urls: list[str], max_bytes: int) -> tuple[bytes, str]:
    failures: list[str] = []
    for url in urls:
        try:
            return download(url, max_bytes=max_bytes), url
        except Exception as error:
            failures.append(f"{url}: {error}")
    raise RuntimeError("all source mirrors failed:\n- " + "\n- ".join(failures))


def download_consensus(urls: list[str], max_bytes: int) -> bytes:
    successful: list[tuple[str, bytes]] = []
    failures: list[str] = []
    for url in urls:
        try:
            successful.append((url, download(url, max_bytes=max_bytes)))
        except Exception as error:
            failures.append(f"{url}: {error}")
    if not successful:
        raise RuntimeError("all source mirrors failed:\n- " + "\n- ".join(failures))
    hashes = {hashlib.sha256(payload).hexdigest() for _, payload in successful}
    if len(hashes) != 1:
        details = ", ".join(
            f"{url}={hashlib.sha256(payload).hexdigest()}"
            for url, payload in successful
        )
        raise ValueError(f"source mirrors disagree: {details}")
    return successful[0][1]


def normalize_candidate(text: str, version: int, minimum: int, maximum: int) -> str:
    raw_values = [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    parsed = tuple(ipaddress.ip_network(value, strict=True) for value in raw_values)
    if any(network.version != version for network in parsed):
        raise ValueError(f"IPv{version} source contains a network from another address family")
    # Collapsing preserves the exact address union while safely repairing upstream
    # duplicates, overlaps, and adjacent ranges before validation and publication.
    networks = tuple(sorted(ipaddress.collapse_addresses(parsed), key=network_sort_key))
    errors = validate_networks(networks, version)
    if not minimum <= len(networks) <= maximum:
        errors.append(
            f"IPv{version} count {len(networks)} is outside {minimum}..{maximum}"
        )
    if errors:
        raise ValueError("; ".join(errors[:20]))
    return "\n".join(str(network) for network in networks) + "\n"


def _selectors_match(attributes: frozenset[str], selectors: frozenset[str]) -> bool:
    return all(
        selector[1:] not in attributes
        if selector.startswith("-")
        else selector in attributes
        for selector in selectors
    )


def resolve_domain_files(files: dict[str, str], root_name: str) -> DomainSnapshot:
    cache: dict[str, tuple[DomainEntry, ...]] = {}
    active: set[str] = set()

    def resolve(name: str) -> tuple[DomainEntry, ...]:
        if name in cache:
            return cache[name]
        if name in active:
            raise ValueError(f"cyclic domain-list include involving {name}")
        if name not in files:
            raise ValueError(f"domain-list include target is missing: {name}")
        active.add(name)
        entries: list[DomainEntry] = []
        for line_number, raw_line in enumerate(files[name].splitlines(), start=1):
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            tokens = line.split()
            directive = tokens[0]
            attributes = frozenset(
                token[1:] for token in tokens[1:] if token.startswith("@")
            )
            if directive.startswith("include:"):
                target = directive.split(":", 1)[1].lower()
                entries.extend(
                    entry
                    for entry in resolve(target)
                    if _selectors_match(entry.attributes, attributes)
                )
                continue

            if ":" in directive:
                prefix, value = directive.split(":", 1)
            else:
                prefix, value = "domain", directive
            kind = {
                "domain": "suffix",
                "full": "exact",
                "keyword": "keyword",
                "regexp": "regexp",
            }.get(prefix)
            if kind is None or not value:
                raise ValueError(
                    f"unsupported domain-list directive in {name}:{line_number}: {directive}"
                )
            entries.append(DomainEntry(kind, value.lower(), attributes))
        active.remove(name)
        cache[name] = tuple(entries)
        return cache[name]

    resolved = resolve(root_name.lower())
    exact = tuple(sorted({entry.value for entry in resolved if entry.kind == "exact"}, key=str.casefold))
    suffixes = tuple(
        sorted({entry.value for entry in resolved if entry.kind == "suffix"}, key=str.casefold)
    )
    keywords = tuple(
        sorted({entry.value for entry in resolved if entry.kind == "keyword"}, key=str.casefold)
    )
    regexes = {entry.value for entry in resolved if entry.kind == "regexp"}
    return DomainSnapshot(exact, suffixes, keywords, len(regexes))


def domain_files_from_archive(payload: bytes) -> dict[str, str]:
    files: dict[str, str] = {}
    total_size = 0
    with tarfile.open(fileobj=BytesIO(payload), mode="r:gz") as archive:
        for member in archive.getmembers():
            parts = PurePosixPath(member.name).parts
            if not member.isfile() or "data" not in parts:
                continue
            data_index = parts.index("data")
            relative_parts = parts[data_index + 1 :]
            if len(relative_parts) != 1:
                continue
            if member.size > 2_000_000:
                raise ValueError(f"oversized domain-list member: {member.name}")
            total_size += member.size
            if total_size > 24_000_000:
                raise ValueError("domain-list archive expands beyond the safety limit")
            extracted = archive.extractfile(member)
            if extracted is None:
                raise ValueError(f"cannot read domain-list member: {member.name}")
            files[relative_parts[0].lower()] = extracted.read().decode("utf-8")
    if "cn" not in files:
        raise ValueError("domain-list archive does not contain data/cn")
    return files


def normalize_domain_snapshot(
    snapshot: DomainSnapshot, minimum: int, maximum: int
) -> dict[str, str]:
    if not minimum <= snapshot.total <= maximum:
        raise ValueError(
            f"domain count {snapshot.total} is outside {minimum}..{maximum}"
        )
    if "cn" not in snapshot.suffixes:
        raise ValueError("domain source no longer contains the required cn suffix")
    if snapshot.skipped_regexes > 100:
        raise ValueError(
            f"unsupported domain regex count {snapshot.skipped_regexes} exceeds 100"
        )
    return {
        "domain-exact.txt": "\n".join(snapshot.exact) + ("\n" if snapshot.exact else ""),
        "domain-suffixes.txt": "\n".join(snapshot.suffixes) + "\n",
        "domain-keywords.txt": "\n".join(snapshot.keywords) + ("\n" if snapshot.keywords else ""),
        "domain-metadata.json": json.dumps(
            {
                "exact": len(snapshot.exact),
                "suffixes": len(snapshot.suffixes),
                "keywords": len(snapshot.keywords),
                "skipped_regexes": snapshot.skipped_regexes,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
    }


def _text(values: tuple[str, ...], *, numeric: bool = False) -> str:
    ordered = sorted(set(values), key=(int if numeric else str.casefold))
    return "\n".join(ordered) + ("\n" if ordered else "")


def _source_path(root: Path, source_id: str, category: str) -> Path:
    return root / "upstream" / "sources" / source_id / f"{category}.txt"


def _validate_count(source: dict[str, Any], total: int) -> None:
    if not source["min_entries"] <= total <= source["max_entries"]:
        raise ValueError(
            f"{source['id']} count {total} is outside "
            f"{source['min_entries']}..{source['max_entries']}"
        )


def guard_source_drift(
    previous_count: int, observed_count: int, max_drop_ratio: float, source_id: str
) -> None:
    if previous_count <= 0:
        return
    drop_ratio = max(0.0, (previous_count - observed_count) / previous_count)
    if drop_ratio > max_drop_ratio:
        raise ValueError(
            f"source drift for {source_id}: count would drop by {drop_ratio:.2%}"
        )


def _fetch_source(source: dict[str, Any]) -> tuple[dict[str, tuple[str, ...]], dict[str, Any]]:
    if source.get("strategy") == "consensus":
        payload = download_consensus(source["urls"], source["max_bytes"])
        selected_url = "consensus of available mirrors"
    else:
        payload, selected_url = download_first(source["urls"], source["max_bytes"])

    kind = source["kind"]
    extra: dict[str, Any] = {}
    if kind == "domain-list-community":
        snapshot = resolve_domain_files(
            domain_files_from_archive(payload), source["root"]
        )
        _validate_count(source, snapshot.total)
        values = {
            "domain-exact": snapshot.exact,
            "domain-suffixes": snapshot.suffixes,
            "domain-keywords": snapshot.keywords,
        }
        extra["skipped_regexes"] = snapshot.skipped_regexes
    elif kind == "dnsmasq-domains":
        domains = parse_dnsmasq_domains(payload.decode("utf-8"))
        _validate_count(source, len(domains))
        values = {"domain-suffixes": domains}
    elif kind == "cidr":
        content = normalize_candidate(
            payload.decode("utf-8"),
            source["version"],
            source["min_entries"],
            source["max_entries"],
        )
        values = {source["category"]: tuple(content.splitlines())}
    elif kind == "mixed-cidr":
        parsed = [
            ipaddress.ip_network(line.strip(), strict=True)
            for line in payload.decode("utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        normalized: dict[int, tuple[ipaddress._BaseNetwork, ...]] = {}
        for version in (4, 6):
            networks = tuple(
                sorted(
                    ipaddress.collapse_addresses(
                        network for network in parsed if network.version == version
                    ),
                    key=network_sort_key,
                )
            )
            errors = validate_networks(networks, version)
            if errors:
                raise ValueError("; ".join(errors[:20]))
            normalized[version] = networks
        _validate_count(source, sum(len(items) for items in normalized.values()))
        prefix = source["category_prefix"]
        values = {
            f"{prefix}-ipv4": tuple(str(network) for network in normalized[4]),
            f"{prefix}-ipv6": tuple(str(network) for network in normalized[6]),
        }
    elif kind == "rir-statistics":
        snapshot = parse_rir_allocations(payload.decode("utf-8"))
        _validate_count(source, snapshot.total)
        serial_date = datetime.strptime(snapshot.serial_date, "%Y%m%d").date()
        age_days = (datetime.now(ZoneInfo("UTC")).date() - serial_date).days
        if not 0 <= age_days <= source["max_age_days"]:
            raise ValueError(
                f"{source['id']} serial date is {age_days} days old"
            )
        values = {
            "registry-ipv4": snapshot.ipv4,
            "registry-ipv6": snapshot.ipv6,
        }
        extra["serial_date"] = snapshot.serial_date
    elif kind == "asn":
        asns = parse_asn_list(payload.decode("utf-8"))
        _validate_count(source, len(asns))
        values = {"asns": tuple(str(value) for value in asns)}
    else:
        raise ValueError(f"unsupported source kind: {kind}")

    metadata = {
        "id": source["id"],
        "project": source["project"],
        "license": source["license"],
        "selected_url": selected_url,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "counts": {category: len(items) for category, items in values.items()},
        **extra,
    }
    return values, metadata


def _load_source_snapshot(
    root: Path, source: dict[str, Any]
) -> tuple[dict[str, tuple[str, ...]], dict[str, Any]]:
    values: dict[str, tuple[str, ...]] = {}
    for category in source.get("categories", [source.get("category")]):
        if not category:
            continue
        path = _source_path(root, source["id"], category)
        if not path.exists():
            raise FileNotFoundError(f"no last verified snapshot for {source['id']}")
        values[category] = tuple(
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        )
    metadata_path = root / "upstream" / "sources" / source["id"] / "metadata.json"
    metadata = (
        json.loads(metadata_path.read_text(encoding="utf-8"))
        if metadata_path.exists()
        else {"id": source["id"], "counts": {k: len(v) for k, v in values.items()}}
    )
    return values, metadata


def _compress_domains(values: set[str]) -> tuple[str, ...]:
    kept: list[str] = []
    for value in sorted(values, key=lambda item: (item.count("."), item.casefold())):
        labels = value.split(".")
        if any(".".join(labels[index:]) in values for index in range(1, len(labels))):
            continue
        kept.append(value)
    return tuple(sorted(kept, key=str.casefold))


def _collapse_network_values(values: set[str], version: int) -> tuple[str, ...]:
    parsed = [ipaddress.ip_network(value, strict=True) for value in values]
    collapsed = tuple(sorted(ipaddress.collapse_addresses(parsed), key=network_sort_key))
    errors = validate_networks(collapsed, version)
    if errors:
        raise ValueError("; ".join(errors[:20]))
    return tuple(str(network) for network in collapsed)


def _guard_ip_coverage(
    previous: tuple[str, ...], observed: tuple[str, ...], max_drop_ratio: float
) -> None:
    if not previous:
        return
    previous_total = sum(ipaddress.ip_network(value).num_addresses for value in previous)
    observed_total = sum(ipaddress.ip_network(value).num_addresses for value in observed)
    drop_ratio = max(0.0, (previous_total - observed_total) / previous_total)
    if drop_ratio > max_drop_ratio:
        raise ValueError(
            "IP coverage circuit breaker: "
            f"address coverage would drop by {drop_ratio:.2%}"
        )


def _seed_previous(root: Path, category: str, lifecycle_exists: bool) -> tuple[str, ...]:
    aggregate_name = {
        "domain-exact": "domain-exact.txt",
        "domain-suffixes": "domain-suffixes.txt",
        "domain-keywords": "domain-keywords.txt",
        "asns": "asns.txt",
    }[category]
    path = root / "upstream" / aggregate_name
    values = set(path.read_text(encoding="utf-8").splitlines()) if path.exists() else set()
    if not lifecycle_exists:
        legacy_name = {
            "domain-exact": "exact-domains.txt",
            "domain-suffixes": "domain-suffixes.txt",
            "domain-keywords": "domain-keywords.txt",
            "asns": "asns.txt",
        }[category]
        legacy = root / "rules" / legacy_name
        if legacy.exists():
            values.update(
                line.strip()
                for line in legacy.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            )
    return tuple(sorted((value for value in values if value), key=str.casefold))


def update(root: Path = ROOT) -> list[Path]:
    config = json.loads((root / "config" / "sources.json").read_text(encoding="utf-8"))
    candidates: dict[Path, str] = {}
    snapshots: dict[str, dict[str, tuple[str, ...]]] = {}
    source_metadata: dict[str, dict[str, Any]] = {}
    statuses: dict[str, str] = {}

    # Every source refreshes independently. A failed source reuses only its own
    # last verified snapshot, so healthy sources can still advance.
    for source in config["sources"]:
        try:
            values, metadata = _fetch_source(source)
            try:
                old_values, _ = _load_source_snapshot(root, source)
            except FileNotFoundError:
                old_values = {}
            guard_source_drift(
                sum(len(items) for items in old_values.values()),
                sum(len(items) for items in values.values()),
                source.get("max_drop_ratio", 0.2),
                source["id"],
            )
            statuses[source["id"]] = "refreshed"
            for category, items in values.items():
                candidates[_source_path(root, source["id"], category)] = _text(
                    items, numeric=(category == "asns")
                )
            candidates[
                root / "upstream" / "sources" / source["id"] / "metadata.json"
            ] = json.dumps(metadata, indent=2, sort_keys=True) + "\n"
        except Exception as error:
            values, metadata = _load_source_snapshot(root, source)
            statuses[source["id"]] = f"retained after refresh failure: {type(error).__name__}"
        snapshots[source["id"]] = values
        source_metadata[source["id"]] = metadata

    unions: dict[str, set[str]] = {}
    excluded_unions: dict[str, set[str]] = {}
    for source in config["sources"]:
        values = snapshots[source["id"]]
        target = (
            excluded_unions
            if source.get("contributes_to_aggregate", True) is False
            else unions
        )
        for category, items in values.items():
            target.setdefault(category, set()).update(items)

    observed = {
        "domain-exact": tuple(sorted(unions.get("domain-exact", set()), key=str.casefold)),
        "domain-suffixes": _compress_domains(unions.get("domain-suffixes", set())),
        "domain-keywords": tuple(sorted(unions.get("domain-keywords", set()), key=str.casefold)),
        "asns": tuple(sorted(unions.get("asns", set()), key=int)),
        "ipv4": _collapse_network_values(unions.get("ipv4", set()), 4),
        "ipv6": _collapse_network_values(unions.get("ipv6", set()), 6),
    }
    suffixes = set(observed["domain-suffixes"])
    observed["domain-exact"] = tuple(
        value
        for value in observed["domain-exact"]
        if not any(
            ".".join(value.split(".")[index:]) in suffixes
            for index in range(len(value.split(".")))
        )
    )

    bounds = config["aggregate_bounds"]
    domain_total = sum(len(observed[name]) for name in ("domain-exact", "domain-suffixes", "domain-keywords"))
    for name, total in (
        ("domain", domain_total),
        ("ipv4", len(observed["ipv4"])),
        ("ipv6", len(observed["ipv6"])),
        ("asn", len(observed["asns"])),
    ):
        if not bounds[name]["min_entries"] <= total <= bounds[name]["max_entries"]:
            raise ValueError(
                f"aggregate {name} count {total} is outside "
                f"{bounds[name]['min_entries']}..{bounds[name]['max_entries']}"
            )

    registry_audit: dict[str, dict[str, int | float]] = {}
    for name in ("ipv4", "ipv6"):
        registered = tuple(
            sorted(
                unions.get(f"registry-{name}", set()),
                key=lambda value: network_sort_key(ipaddress.ip_network(value)),
            )
        )
        if not registered:
            continue
        audit = registry_coverage(observed[name], registered)
        if audit.missing_ratio > config["policy"]["max_registry_coverage_gap_ratio"]:
            raise ValueError(
                f"{name} registry coverage gap {audit.missing_ratio:.2%} exceeds "
                f"{config['policy']['max_registry_coverage_gap_ratio']:.2%}"
            )
        registry_audit[name] = {
            "registered_addresses": audit.registered_addresses,
            "missing_addresses": audit.missing_addresses,
            "missing_ratio": audit.missing_ratio,
        }

    for name in ("ipv4", "ipv6"):
        previous_path = root / "upstream" / f"{name}.txt"
        previous = tuple(previous_path.read_text(encoding="utf-8").splitlines()) if previous_path.exists() else ()
        _guard_ip_coverage(
            previous, observed[name], config["policy"]["max_ip_coverage_drop_ratio"]
        )
        candidates[previous_path] = "\n".join(observed[name]) + "\n"

    lifecycle_path = root / "upstream" / "lifecycle.json"
    loaded_lifecycle = (
        json.loads(lifecycle_path.read_text(encoding="utf-8"))
        if lifecycle_path.exists()
        else {}
    )
    lifecycle_exists = loaded_lifecycle.get("schema_version") == 3
    lifecycle = loaded_lifecycle if lifecycle_exists else {"missing_counts": {}}
    observation_day = datetime.now(ZoneInfo("Asia/Shanghai")).date().isoformat()
    observation_id = hashlib.sha256(
        json.dumps(
            {
                "day": observation_day,
                "sources": {
                    source_id: metadata.get("sha256")
                    for source_id, metadata in source_metadata.items()
                },
            },
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    all_sources_refreshed = all(status == "refreshed" for status in statuses.values())
    policy = LifecyclePolicy(
        retire_after_successes=config["policy"]["retire_after_successes"],
        max_retire_ratio=config["policy"]["max_retire_ratio"],
        max_retire_count=config["policy"]["max_retire_count"],
    )
    lifecycle_report: dict[str, dict[str, int]] = {}
    next_missing: dict[str, dict[str, int]] = {}
    aggregate_names = {
        "domain-exact": "domain-exact.txt",
        "domain-suffixes": "domain-suffixes.txt",
        "domain-keywords": "domain-keywords.txt",
        "asns": "asns.txt",
    }
    category_advancement: dict[str, bool] = {}
    for category, filename in aggregate_names.items():
        advance_category = can_advance_category(
            config["sources"],
            statuses,
            category,
            lifecycle.get("observation_day"),
            observation_day,
        )
        category_advancement[category] = advance_category
        result = reconcile_values(
            _seed_previous(root, category, lifecycle_exists),
            observed[category],
            lifecycle.get("missing_counts", {}).get(category, {}),
            policy,
            advance_missing=advance_category,
        )
        next_missing[category] = result.missing_counts
        lifecycle_report[category] = {
            "added": len(result.added),
            "retained_missing": len(result.missing_counts),
            "retired": len(result.retired),
        }
        candidates[root / "upstream" / filename] = _text(
            result.values, numeric=(category == "asns")
        )

    for category, filename in aggregate_names.items():
        excluded_values = excluded_unions.get(category, set()) - set(observed[category])
        if not excluded_values:
            lifecycle_report[category]["removed_excluded_source"] = 0
            continue
        aggregate_path = root / "upstream" / filename
        before_excluded_repair = tuple(candidates[aggregate_path].splitlines())
        repaired_values = tuple(
            value for value in before_excluded_repair if value not in excluded_values
        )
        candidates[aggregate_path] = _text(
            repaired_values, numeric=(category == "asns")
        )
        repaired_value_set = set(repaired_values)
        next_missing[category] = {
            value: count
            for value, count in next_missing.get(category, {}).items()
            if value in repaired_value_set
        }
        lifecycle_report[category]["retained_missing"] = len(next_missing[category])
        lifecycle_report[category]["removed_excluded_source"] = (
            len(before_excluded_repair) - len(repaired_values)
        )

    exact_path = root / "upstream" / "domain-exact.txt"
    suffix_path = root / "upstream" / "domain-suffixes.txt"
    high_risk_suffixes = set(read_values(root / "config" / "high-risk-domain-suffixes.txt"))
    before_safety_exact = tuple(candidates[exact_path].splitlines())
    before_safety_suffixes = tuple(candidates[suffix_path].splitlines())
    safety_repair = remove_high_risk_domain_rules(
        exact=before_safety_exact,
        suffixes=before_safety_suffixes,
        high_risk_suffixes=high_risk_suffixes,
        missing_counts={
            "domain-exact": next_missing.get("domain-exact", {}),
            "domain-suffixes": next_missing.get("domain-suffixes", {}),
        },
    )
    candidates[exact_path] = _text(safety_repair.exact)
    candidates[suffix_path] = _text(safety_repair.suffixes)
    next_missing["domain-exact"] = safety_repair.missing_counts["domain-exact"]
    next_missing["domain-suffixes"] = safety_repair.missing_counts["domain-suffixes"]
    lifecycle_report["domain-exact"]["removed_high_risk"] = (
        len(before_safety_exact) - len(safety_repair.exact)
    )
    lifecycle_report["domain-suffixes"]["removed_high_risk"] = (
        len(before_safety_suffixes) - len(safety_repair.suffixes)
    )

    before_repair_exact = safety_repair.exact
    before_repair_suffixes = safety_repair.suffixes
    domain_repair = repair_domain_redundancy(
        exact=before_repair_exact,
        suffixes=before_repair_suffixes,
        missing_counts={
            "domain-exact": next_missing.get("domain-exact", {}),
            "domain-suffixes": next_missing.get("domain-suffixes", {}),
        },
    )
    exact_repaired_count = len(before_repair_exact) - len(domain_repair.exact)
    suffix_repaired_count = len(before_repair_suffixes) - len(domain_repair.suffixes)
    candidates[exact_path] = _text(domain_repair.exact)
    candidates[suffix_path] = _text(domain_repair.suffixes)
    next_missing["domain-exact"] = domain_repair.missing_counts["domain-exact"]
    next_missing["domain-suffixes"] = domain_repair.missing_counts["domain-suffixes"]
    lifecycle_report["domain-exact"]["retained_missing"] = len(next_missing["domain-exact"])
    lifecycle_report["domain-suffixes"]["retained_missing"] = len(
        next_missing["domain-suffixes"]
    )
    lifecycle_report["domain-exact"]["repaired_redundant"] = exact_repaired_count
    lifecycle_report["domain-suffixes"]["repaired_redundant"] = suffix_repaired_count

    candidates[lifecycle_path] = json.dumps(
        {
            "schema_version": 3,
            "observation_day": observation_day,
            "observation_id": observation_id,
            "policy": {
                "retire_after_successes": policy.retire_after_successes,
                "max_retire_ratio": policy.max_retire_ratio,
                "max_retire_count": policy.max_retire_count,
            },
            "missing_counts": next_missing,
        },
        indent=2,
        sort_keys=True,
    ) + "\n"
    skipped_regexes = sum(
        int(metadata.get("skipped_regexes", 0)) for metadata in source_metadata.values()
    )
    domain_counts = {
        "exact": len(candidates[root / "upstream" / "domain-exact.txt"].splitlines()),
        "suffixes": len(candidates[root / "upstream" / "domain-suffixes.txt"].splitlines()),
        "keywords": len(candidates[root / "upstream" / "domain-keywords.txt"].splitlines()),
        "skipped_regexes": skipped_regexes,
    }
    candidates[root / "upstream" / "domain-metadata.json"] = json.dumps(
        domain_counts, indent=2, sort_keys=True
    ) + "\n"
    candidates[root / "upstream" / "update-report.json"] = json.dumps(
        {
            "aggregate_counts": {
                **domain_counts,
                "ipv4": len(observed["ipv4"]),
                "ipv6": len(observed["ipv6"]),
                "asns": len(candidates[root / "upstream" / "asns.txt"].splitlines()),
            },
            "lifecycle": lifecycle_report,
            "registry_coverage": registry_audit,
            "all_sources_refreshed": all_sources_refreshed,
            "category_observation_advanced": category_advancement,
            "excluded_from_aggregate": [
                source["id"]
                for source in config["sources"]
                if source.get("contributes_to_aggregate", True) is False
            ],
            "observation_advanced": any(category_advancement.values()),
            "sources": statuses,
        },
        indent=2,
        sort_keys=True,
    ) + "\n"

    changed: list[Path] = []
    for destination, content in candidates.items():
        if destination.exists() and destination.read_text(encoding="utf-8") == content:
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        temporary.write_text(content, encoding="utf-8", newline="\n")
        temporary.replace(destination)
        changed.append(destination)
    return changed


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch and validate CN rule sources")
    parser.parse_args()
    changed = update()
    if changed:
        print("Updated: " + ", ".join(str(path.relative_to(ROOT)) for path in changed))
    else:
        print("Upstream snapshots are already current")


if __name__ == "__main__":
    main()
