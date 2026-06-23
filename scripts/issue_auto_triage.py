from __future__ import annotations

import ipaddress
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.ruleset import ROOT, read_values

SECTION_RE = re.compile(r"^###\s+(.+?)\s*$", re.MULTILINE)
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$", re.IGNORECASE)
ASN_RE = re.compile(r"^(?:AS)?(\d+)$", re.IGNORECASE)


@dataclass(frozen=True)
class Decision:
    label: str
    close: bool
    state_reason: str
    comment: str


def issue_sections(body: str) -> dict[str, str]:
    matches = list(SECTION_RE.finditer(body or ""))
    sections: dict[str, str] = {}
    for index, match in enumerate(matches):
        key = match.group(1).strip().lower()
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        value = body[start:end].strip()
        sections[key] = value
    return sections


def clean_value(value: str) -> str:
    lines = [line.strip() for line in (value or "").splitlines()]
    lines = [line for line in lines if line and line != "_No response_"]
    return lines[0] if lines else ""


def high_risk_suffixes() -> set[str]:
    path = ROOT / "config" / "high-risk-domain-suffixes.txt"
    if not path.exists():
        return set()
    return {value.lower() for value in read_values(path)}


def normalize_target(target: str) -> str:
    return target.strip().strip("`").strip().lower().removeprefix(".")


def is_high_risk_domain(domain: str, high_risk: set[str]) -> bool:
    value = normalize_target(domain)
    return any(value == suffix or value.endswith("." + suffix) for suffix in high_risk)


def validate_target(target: str, target_type: str) -> tuple[bool, str]:
    value = normalize_target(target)
    kind = target_type.lower().strip()
    if kind in {"domain", "domain suffix"}:
        return bool(DOMAIN_RE.fullmatch(value)), value
    if kind == "ipv4 cidr":
        try:
            network = ipaddress.ip_network(value, strict=True)
            return network.version == 4 and network.is_global, str(network)
        except ValueError:
            return False, value
    if kind == "ipv6 cidr":
        try:
            network = ipaddress.ip_network(value, strict=True)
            return network.version == 6 and network.is_global, str(network)
        except ValueError:
            return False, value
    if kind == "asn":
        match = ASN_RE.fullmatch(value)
        return bool(match and int(match.group(1)) > 0), f"AS{int(match.group(1))}" if match else value
    return False, value


def decide(title: str, body: str) -> Decision:
    sections = issue_sections(body)
    title_lower = title.lower()
    is_wrong_direct = title_lower.startswith("wrong-direct") or "problem target" in sections
    target = clean_value(sections.get("missing target", "") or sections.get("problem target", ""))
    target_type = clean_value(sections.get("target type", ""))
    evidence = clean_value(sections.get("evidence", ""))

    if not target or not target_type or not evidence:
        return Decision(
            label="needs-info",
            close=False,
            state_reason="not_planned",
            comment="Automated triage result: needs-info. The report must include a target, a target type, and public evidence.",
        )

    valid, normalized = validate_target(target, target_type)
    if not valid:
        return Decision(
            label="needs-info",
            close=False,
            state_reason="not_planned",
            comment=f"Automated triage result: needs-info. The target `{target}` is not a valid public {target_type}.",
        )

    if not is_wrong_direct and target_type.lower().strip() in {"domain", "domain suffix"} and is_high_risk_domain(normalized, high_risk_suffixes()):
        return Decision(
            label="wontfix",
            close=True,
            state_reason="not_planned",
            comment=f"Automated triage result: wontfix. `{normalized}` matches the high-risk domain list and will not be auto-promoted into direct rules.",
        )

    return Decision(
        label="ready-for-agent",
        close=False,
        state_reason="not_planned",
        comment=f"Automated triage result: ready-for-agent. Normalized target: `{normalized}`. The request passed deterministic format and evidence checks.",
    )


def write_outputs(decision: Decision) -> None:
    output_path = Path(__import__("os").environ.get("GITHUB_OUTPUT", ""))
    if not output_path:
        print(json.dumps(decision.__dict__, ensure_ascii=False, indent=2))
        return
    delimiter = "AUTO_TRIAGE_COMMENT"
    with output_path.open("a", encoding="utf-8") as handle:
        handle.write(f"label={decision.label}\n")
        handle.write(f"close={'true' if decision.close else 'false'}\n")
        handle.write(f"state_reason={decision.state_reason}\n")
        handle.write(f"comment<<{delimiter}\n{decision.comment}\n{delimiter}\n")


def main() -> None:
    event_path = Path(sys.argv[1])
    event = json.loads(event_path.read_text(encoding="utf-8"))
    issue = event.get("issue", {})
    if "pull_request" in issue:
        write_outputs(Decision("needs-triage", False, "not_planned", "Automated triage skipped pull request issue."))
        return
    write_outputs(decide(issue.get("title", ""), issue.get("body", "")))


if __name__ == "__main__":
    main()
