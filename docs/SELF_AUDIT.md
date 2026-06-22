# Self-audit and known limits

This repository favors reproducibility and safe failure over silently publishing a suspicious update.

## Enforced guarantees

- The scheduled workflow is configured for 00:00 Asia/Shanghai (`16:00 UTC`). GitHub may delay scheduled jobs.
- IPv4 and IPv6 are downloaded through independent GitHub and GitLab mirror URLs; when both respond, their SHA-256 values must agree.
- Domain data is resolved from the MIT-licensed V2Fly `cn` list, including nested includes and attribute filters.
- Invalid, private, reserved, duplicate, overlapping, wrong-family, oversized, or unexpectedly sparse/dense sources fail the update before any file is replaced.
- The strict output filters known globally open suffixes; `max` outputs preserve the complete resolved TLD coverage.
- No output contains a `GEOSITE` directive or LAN range.
- Policy-bearing configuration fragments and policy-free provider files are generated separately.
- The Shadowrocket Standalone Complete Module is generated from the Maximum Coverage Profile and the same verified public-network model; it is not a second hand-maintained rule source.
- The README install button uses an HTTPS Pages bridge that accepts only the repository's exact Shadowrocket module deep link.
- Every output is deterministic, tested, recorded in `manifest.json`, and covered by `SHA256SUMS`.
- A failed check prevents the automated commit and Release.

## Known limits

- GitHub scheduled workflows are not real-time cron and may start after 00:00.
- `GEOIP,CN` accuracy depends on the database bundled with each client.
- V2Fly regular-expression domain entries are not portable across all target clients. They are skipped and counted in `upstream/domain-metadata.json`.
- `IP-ASN` can cover an operator's overseas addresses; clients that require purely geographic routing should use the CIDR or GeoIP subsets instead.
- Domain-keyword rules are intentionally broad and may produce rare false positives.
- There is no universal proxy-rule syntax. The repository provides `[Rule]` fragments, policy-free remote lists, and Clash-compatible classical providers rather than claiming one file works everywhere.
- The Shadowrocket install deep link requires iOS/iPadOS with Shadowrocket installed. Desktop browsers can inspect the module but cannot complete the App handoff.
- The domain archive has two GitHub endpoints but not an independent non-GitHub mirror. A GitHub-wide outage will fail closed and retain the last verified snapshot.

## Maintainer checklist

Before changing source policy, count bounds, or output syntax:

1. Run the source updater against the real upstreams.
2. Build twice and verify no second diff.
3. Run the full unit suite and validator.
4. Inspect `manifest.json`, `SHA256SUMS`, and strict/max count deltas.
5. Confirm the pull-request CI before merging.
