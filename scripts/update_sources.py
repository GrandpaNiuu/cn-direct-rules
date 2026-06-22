from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import sys
import tarfile
import time
import urllib.request
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path, PurePosixPath

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.ruleset import ROOT, network_sort_key, validate_networks


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
    networks = tuple(
        sorted(
            (ipaddress.ip_network(value, strict=True) for value in raw_values),
            key=network_sort_key,
        )
    )
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


def update(root: Path = ROOT) -> list[Path]:
    config = json.loads((root / "config" / "sources.json").read_text(encoding="utf-8"))
    candidates: dict[Path, str] = {}
    for name, version in (("ipv4", 4), ("ipv6", 6)):
        source = config[name]
        payload = download_consensus(source["urls"], source["max_bytes"])
        normalized = normalize_candidate(
            payload.decode("utf-8"),
            version,
            source["min_entries"],
            source["max_entries"],
        )
        candidates[root / "upstream" / f"{name}.txt"] = normalized

    domain_source = config["domains"]
    archive, _ = download_first(domain_source["urls"], domain_source["max_bytes"])
    domain_files = domain_files_from_archive(archive)
    domain_snapshot = resolve_domain_files(domain_files, domain_source["root"])
    normalized_domains = normalize_domain_snapshot(
        domain_snapshot,
        domain_source["min_entries"],
        domain_source["max_entries"],
    )
    for filename, content in normalized_domains.items():
        candidates[root / "upstream" / filename] = content

    changed: list[Path] = []
    for destination, content in candidates.items():
        if destination.exists() and destination.read_text(encoding="utf-8") == content:
            continue
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
