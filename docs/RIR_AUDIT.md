# Global RIR CN audit layer

This repository should not describe its main rule set as absolutely complete. The practical target is high coverage plus auditable gaps.

The RIR audit layer adds a separate registration-scope view for resources whose delegated statistics records use country code `CN`. It is intentionally audit-only. Registration country is not equivalent to current physical location, current BGP reachability, or a guarantee that a network should be routed directly.

## Scope

The audit layer is designed to collect these records from the five Regional Internet Registries:

- APNIC
- ARIN
- RIPE NCC
- LACNIC
- AFRINIC

For each source it should parse `ipv4`, `ipv6`, and `asn` records whose status is `allocated` or `assigned` and whose country code is `CN`.

## Intended outputs

The audit output should be separate from the strict direct-routing rule set:

- `upstream/rir-global/ipv4.txt`
- `upstream/rir-global/ipv6.txt`
- `upstream/rir-global/asns.txt`
- `upstream/audit/asn-diff.json`
- `upstream/audit/rir-cn-summary.json`
- `dist/registry/cn-global-allocated.conf`
- `dist/registry/cn-rir-asn.conf`
- `dist/rir-audit-manifest.json`

`upstream/asns.txt` remains the high-confidence ASN set used by the main rules. RIR-derived ASNs are compared against it in the audit report instead of being merged blindly.

## Promotion rule

A resource discovered only through RIR registration data should not be promoted into the main direct rules without additional confidence signals, such as stable BGP origin observation, upstream list agreement, or maintainer review.

## Wording rule

Use wording such as “high coverage”, “multi-source”, “auditable”, and “gap report”. Do not use “absolute full coverage”, “no omissions”, or equivalent claims.
