# Self-audit and known limits

This repository favors traceable data, safe failure, and reproducible output over silently publishing a suspicious update.

## Enforced guarantees

- The workflow checks for updates every day at 00:00 Asia/Shanghai (`16:00 UTC`). GitHub may start a scheduled job late.
- Every configured source has a project URL, license, count boundary, download-size limit, content hash, metadata file, and last verified snapshot under `upstream/sources/`.
- Sources refresh independently. A failed source reuses only its own last verified snapshot, while healthy sources may continue updating.
- IPv4 and IPv6 use independent APNIC/BGP-derived projects. The hourly chnroutes2 feed closes additional IPv4 routing gaps. Duplicate, overlapping, and adjacent ranges are collapsed without changing their address union.
- APNIC delegated statistics are parsed independently, checked for recency, and compared with routed coverage. A registry gap greater than 0.5% rejects the refresh.
- Domain coverage combines V2Fly's structured `cn` data with felixonmars' actively maintained mainland DNS-routing, Apple China, and Google China lists. Commented-out dnsmasq entries are treated as removed and never imported.
- Operator slices for China Telecom, China Mobile, China Unicom, CERNET, and CSTNET are generated independently from BGP classifications and are not silently merged into the canonical model.
- ASN data is parsed only from explicit `IP-ASN,<number>` records in the daily ASN-China snapshot.
- A disappeared domain or ASN remains for three Beijing-calendar-day observations on which every source relevant to that category refreshed successfully. Re-running the updater on the same day or a relevant-source failure does not age it toward deletion.
- If one observation would retire more than 1% or 1,000 rules, the retirement circuit breaker rejects the entire refresh. IP address coverage may not drop by more than 1%.
- All candidates are downloaded, parsed, aggregated, and checked before any repository file is replaced.
- Private, reserved, wrong-family, malformed, unexpectedly small/large, or non-deterministic input is rejected.
- No output contains a `GEOSITE` directive or private-network range. IPv6 remains included.
- `manifest.json`, `SHA256SUMS`, `upstream/update-report.json`, and per-source metadata make outputs auditable.
- The workflow builds, tests, and validates before committing only `upstream/` and `dist/` to `main`. It creates no Release and no tag.

## What “invalid removal” means here

The project does not delete a domain merely because one machine cannot open it. DNS failures, regional CDN behavior, temporary maintenance, and blocking can all make active services look dead. Large-scale probing would also be noisy and unreliable.

Instead, a rule becomes eligible for removal only after all relevant successful source snapshots stop reporting it on three distinct Beijing calendar days. Source download failures do not count. The update report records additions, retained missing rules, and retirements.

## Known limits

- No public list can guarantee that every Chinese service is reachable at every moment.
- Domain entries describe mainland DNS/direct-routing suitability, not a promise that every website is currently online.
- APNIC allocation country records describe initial registration, not current route announcement or physical location; they remain a separate artifact and audit.
- Operator slices may contain provider routes outside the conservative canonical aggregate and should be installed only when that operator-specific behavior is wanted.
- `IP-ASN` may include an operator's overseas routes. Users requiring strictly geographic routing should prefer the CIDR or GeoIP-only artifacts.
- `GEOIP,CN` accuracy depends on the database bundled with each client.
- V2Fly regular-expression entries are skipped and counted because clients do not share a portable regex syntax.
- Maximum coverage can cause more false direct-routing than strict coverage. Shadowrocket's complete module/configuration intentionally use maximum coverage.
- Shadowrocket automatic refresh depends on iOS Background App Refresh and the app's module/configuration update setting.

## Maintainer checklist

1. Run `python scripts/update_sources.py` against the real upstreams.
2. Run it again; an identical observation must not age missing rules.
3. Run `python scripts/build.py`.
4. Run `python -m unittest discover -s tests -v` and `python scripts/validate.py`.
5. Inspect `upstream/update-report.json`, `dist/manifest.json`, and count deltas before merging.
