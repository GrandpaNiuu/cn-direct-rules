# Full automation policy

This project is designed to run without manual triage for routine rule maintenance.

The main automated path is `.github/workflows/update.yml`:

1. Refresh guarded upstream snapshots with `scripts/update_sources.py`.
2. Refresh automated RIR audit reports with `scripts/auto_maintain.py`.
3. Refresh automated BGP origin audit reports with `scripts/bgp_auto.py`.
4. Build generated rule files with `scripts/build.py`.
5. Run tests and `scripts/validate.py`.
6. Commit verified `upstream` and `dist` changes.

## Promotion model

The strict rule outputs stay controlled by the existing high-confidence source pipeline. Audit-only data is still refreshed automatically, but it is not blindly promoted into strict rules.

This avoids a common failure mode: making the rule set look more complete while increasing false positives.

## Automated RIR audit layer

`scripts/auto_maintain.py` automatically checks the five Regional Internet Registries for resources whose delegated records use country code `CN`:

- APNIC
- ARIN
- RIPE NCC
- LACNIC
- AFRINIC

It parses IPv4, IPv6, and ASN records with status `allocated` or `assigned`.

Generated audit outputs are written under `upstream`, not `dist`, so the existing deterministic `dist` validation contract remains intact.

Expected RIR outputs include:

- `upstream/rir-global/ipv4.txt`
- `upstream/rir-global/ipv6.txt`
- `upstream/rir-global/asns.txt`
- `upstream/rir-global/sources/<rir>/ipv4.txt`
- `upstream/rir-global/sources/<rir>/ipv6.txt`
- `upstream/rir-global/sources/<rir>/asns.txt`
- `upstream/audit/asn-diff.json`
- `upstream/audit/coverage.json`
- `upstream/audit/coverage.md`
- `upstream/audit/rir-cn-summary.json`

## Automated BGP origin audit layer

`scripts/bgp_auto.py` automatically tries recent RouteViews prefix-to-AS snapshots and compares observed origin ASNs against the main ASN set and the RIR CN ASN audit set.

Expected BGP outputs include:

- `upstream/bgp-origin/prefixes-main-asn.txt`
- `upstream/bgp-origin/prefixes-rir-only-asn.txt`
- `upstream/bgp-origin/asns-main-seen.txt`
- `upstream/bgp-origin/asns-rir-only-seen.txt`
- `upstream/audit/bgp-origin-summary.json`
- `upstream/audit/bgp-origin-status.json` when refresh fails

BGP-observed data is audit-only unless a deterministic promotion rule is added later.

## Automated issue triage

`.github/workflows/issue-auto-triage.yml` runs on issue creation, edit, and reopen. It calls `scripts/issue_auto_triage.py`, applies one of the canonical triage labels, comments with the automated decision, and closes deterministic `wontfix` cases.

The issue workflow does not modify rule data directly. External reports can influence the automation queue only after deterministic validation.

## No manual review assumption

When manual review is not part of the operating model, the repository must prefer conservative automatic promotion and aggressive automatic reporting.

That means:

- high-confidence sources can affect strict outputs;
- registration-only or BGP-observed data should first affect audit outputs;
- automated reports should expose gaps, overlaps, and source failures;
- failed audit refreshes should not break the main rule build when previous verified snapshots exist;
- external issue reports are classified automatically but cannot directly poison strict rule outputs.
