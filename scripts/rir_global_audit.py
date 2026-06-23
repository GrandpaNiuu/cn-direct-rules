from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, Iterable

from scripts.ruleset import network_sort_key, validate_networks


ACCEPTED_STATUSES = {"allocated", "assigned"}


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

    serial_date = ""
    ipv4: list[ipaddress.IPv4Network] = []
    ipv6: list[ipaddress.IPv6Network] = []
    asns: set[int] = set()

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split("|")
        if len(fields) >= 7 and fields[0] == "2" and fields[1] == registry:
            serial_date = fields[2]
            continue
        if (
            len(fields) < 7
            or fields[0] != registry
            or fields[1] != country
            or fields[2] not in {"ipv4", "ipv6", "asn"}
            or fields[6] not in statuses
        ):
            continue

        resource_type, start_value, count_value = fields[2], fields[3], fields[4]
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
        raise ValueError(f"{registry} delegated statistics header has no valid serial date")

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
