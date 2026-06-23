# Full automation policy

This project is designed to run without manual triage for routine rule maintenance.

The main automated path is `.github/workflows/update.yml`:

1. Refresh guarded upstream snapshots with `scripts/update_sources.py`.
2. Refresh automated audit reports with `scripts/auto_maintain.py`.
3. Build generated rule files with `scripts/build.py`.
4. Run tests and `scripts/validate.py`.
5. Commit verified `upstream` and `dist` changes.

## Promotion model

The strict rule outputs stay controlled by the existing high-confidence source pipeline. Audit-only data is still refreshed automatically, but it is not blindly promoted into strict rules.

This avoids a common failure mode: making the rule set look more complete while increasing false positives.

## Automated audit layer

`scripts/auto_maintain.py` automatically checks the five Regional Internet Registries for resources whose delegated records use country code `CN`:

- APNIC
- ARIN
- RIPE NCC
- LACNIC
- AFRINIC

It parses IPv4, IPv6, and ASN records with status `allocated` or `assigned`.

Generated audit outputs are written under `upstream`, not `dist`, so the existing deterministic `dist` validation contract remains intact.

Expected outputs include:

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

## No manual review assumption

When manual review is not part of the operating model, the repository must prefer conservative automatic promotion and aggressive automatic reporting.

That means:

- high-confidence sources can affect strict outputs;
- registration-only or BGP-observed data should first affect audit outputs;
- automated reports should expose gaps, overlaps, and source failures;
- failed audit refreshes should not break the main rule build when previous verified snapshots exist.

## Next automation stage

The next safe stage is automated BGP origin reporting. It should follow the same rule: write machine-readable audit reports first, then promote only candidates that meet deterministic confidence thresholds.
