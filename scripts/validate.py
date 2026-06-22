from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.ruleset import ROOT, load_rules, render_outputs, validate_rules


def main() -> None:
    rules = load_rules()
    errors = validate_rules(rules)
    expected = render_outputs(rules)

    for relative_name, expected_content in expected.items():
        path = ROOT / "dist" / relative_name
        if not path.exists():
            errors.append(f"missing generated file: dist/{relative_name}")
            continue
        actual = path.read_text(encoding="utf-8")
        if actual != expected_content:
            errors.append(f"stale or modified generated file: dist/{relative_name}")

    actual_files = {
        path.relative_to(ROOT / "dist").as_posix()
        for path in (ROOT / "dist").rglob("*")
        if path.is_file()
    }
    unexpected_files = sorted(actual_files - set(expected))
    if unexpected_files:
        errors.append(
            "unexpected generated files: "
            + ", ".join(f"dist/{name}" for name in unexpected_files)
        )

    all_generated = "\n".join(expected.values()).upper()
    if "GEOSITE," in all_generated:
        errors.append("generated output must not contain GEOSITE")
    if "DOMAIN-SUFFIX,CN,DIRECT" not in expected["cn.conf"].upper():
        errors.append("generated cn.conf is missing DOMAIN-SUFFIX,cn,DIRECT")
    if expected["cn.conf"].upper().count("GEOIP,CN,DIRECT") != 1:
        errors.append("generated cn.conf must contain GEOIP,CN,DIRECT exactly once")
    if expected["cn-max.conf"].upper().count("GEOIP,CN,DIRECT") != 1:
        errors.append("generated cn-max.conf must contain GEOIP,CN,DIRECT exactly once")
    for relative_name in (
        "clash/cn.yaml",
        "clash/cn-max.yaml",
        "rule-set/cn.list",
        "rule-set/cn-max.list",
    ):
        if ",DIRECT" in expected[relative_name]:
            errors.append(f"policy-free provider embeds a policy: {relative_name}")

    manifest = json.loads(expected["manifest.json"])
    for relative_name, expected_hash in manifest["files"].items():
        actual_hash = hashlib.sha256(expected[relative_name].encode("utf-8")).hexdigest()
        if actual_hash != expected_hash:
            errors.append(f"manifest hash mismatch for {relative_name}")

    checksums = {
        relative_name: digest
        for line in expected["SHA256SUMS"].splitlines()
        for digest, relative_name in (line.split("  ", 1),)
    }
    for relative_name, content in expected.items():
        if relative_name == "SHA256SUMS":
            continue
        actual_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if checksums.get(relative_name) != actual_hash:
            errors.append(f"SHA256SUMS mismatch for {relative_name}")

    if errors:
        raise SystemExit("Validation failed:\n- " + "\n- ".join(errors))
    print(
        "Validation passed: "
        f"{len(rules.exact_domains)} exact domains, "
        f"{len(rules.domain_suffixes)} suffixes, "
        f"{len(rules.domain_keywords)} keywords, "
        f"{len(rules.max_domain_suffixes)} max suffixes, "
        f"{len(rules.ipv4)} IPv4, {len(rules.ipv6)} IPv6, {len(rules.asns)} ASNs"
    )


if __name__ == "__main__":
    main()
