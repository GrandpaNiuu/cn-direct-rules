# Self-audit and known limits

This repository favors reproducibility and safe failure over silently publishing a suspicious update.

## Enforced guarantees

- The scheduled workflow is configured for 00:00 Asia/Shanghai (`16:00 UTC`). GitHub may delay scheduled jobs.
- IPv4 and IPv6 are downloaded through independent GitHub and GitLab mirror URLs; when both respond, their SHA-256 values must agree.
- Domain data is resolved from the MIT-licensed V2Fly `cn` list, including nested includes and attribute filters.
- Invalid, private, reserved, wrong-family, oversized, or unexpectedly sparse/dense sources fail the refresh before any file is replaced. Duplicate, overlapping, and adjacent CIDRs are safely collapsed without changing their combined address coverage, then validated again.
- The strict output filters known globally open suffixes; `max` outputs preserve the complete resolved TLD coverage.
- No output contains a `GEOSITE` directive or LAN range.
- Policy-bearing configuration fragments and policy-free provider files are generated separately.
- The Shadowrocket Standalone Complete Module is generated from the Maximum Coverage Profile and the same verified public-network model; it is not a second hand-maintained rule source.
- The Shadowrocket Standalone Complete Configuration is generated from that same model and ends with a proxy fallback. It is intended for clean setup or reset because importing it replaces the current configuration.
- The README install buttons use an HTTPS Pages bridge that accepts only the repository's exact module and configuration deep links.
- Every output is deterministic, tested, recorded in `manifest.json`, and covered by `SHA256SUMS`.
- If every upstream attempt fails, the workflow retains the last verified snapshots and still rebuilds, tests, and validates them. Any failed build or check prevents an automated commit and push to `main`.

## Known limits

- GitHub scheduled workflows are not real-time cron and may start after 00:00.
- `GEOIP,CN` accuracy depends on the database bundled with each client.
- V2Fly regular-expression domain entries are not portable across all target clients. They are skipped and counted in `upstream/domain-metadata.json`.
- `IP-ASN` can cover an operator's overseas addresses; clients that require purely geographic routing should use the CIDR or GeoIP subsets instead.
- Domain-keyword rules are intentionally broad and may produce rare false positives.
- There is no universal proxy-rule syntax. The repository provides `[Rule]` fragments, policy-free remote lists, and Clash-compatible classical providers rather than claiming one file works everywhere.
- Shadowrocket install deep links require iOS/iPadOS with Shadowrocket installed. Desktop browsers can inspect the files but cannot complete the App handoff.
- Automatic app-side refresh depends on iOS Background App Refresh and the corresponding module or configuration auto-update option in Shadowrocket.
- The domain archive has two GitHub endpoints but not an independent non-GitHub mirror. A GitHub-wide outage will fail closed and retain the last verified snapshot.

## Maintainer checklist

Before changing source policy, count bounds, or output syntax:

1. Run the source updater against the real upstreams.
2. Build twice and verify no second diff.
3. Run the full unit suite and validator.
4. Inspect `manifest.json`, `SHA256SUMS`, and strict/max count deltas.
5. Confirm the pull-request CI before merging.
