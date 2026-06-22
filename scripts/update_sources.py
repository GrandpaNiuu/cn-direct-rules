from __future__ import annotations

import argparse
import ipaddress
import json
import sys
import time
import urllib.request
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.ruleset import ROOT, network_sort_key, validate_networks


USER_AGENT = "GrandpaNiuu/cn-direct-rules source updater"


def download(url: str, attempts: int = 3) -> str:
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(request, timeout=45) as response:
                return response.read().decode("utf-8")
        except Exception as error:  # network failures vary by runner and provider
            last_error = error
            if attempt < attempts:
                time.sleep(2**attempt)
    raise RuntimeError(f"failed to download {url} after {attempts} attempts") from last_error


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


def update(root: Path = ROOT) -> list[Path]:
    config = json.loads((root / "config" / "sources.json").read_text(encoding="utf-8"))
    candidates: dict[Path, str] = {}
    for name, version in (("ipv4", 4), ("ipv6", 6)):
        source = config[name]
        text = download(source["url"])
        normalized = normalize_candidate(
            text, version, source["min_entries"], source["max_entries"]
        )
        candidates[root / "upstream" / f"{name}.txt"] = normalized

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
    parser = argparse.ArgumentParser(description="Fetch and validate public CN CIDR sources")
    parser.parse_args()
    changed = update()
    if changed:
        print("Updated: " + ", ".join(str(path.relative_to(ROOT)) for path in changed))
    else:
        print("Upstream snapshots are already current")


if __name__ == "__main__":
    main()
