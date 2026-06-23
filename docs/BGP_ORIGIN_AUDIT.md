# BGP origin audit layer

The BGP origin audit layer compares observed prefix-origin data with the repository's China ASN sets. It is an audit layer, not a direct promotion path into the main rule set.

## Why this is separate

A prefix observed with a China-related origin ASN is useful evidence, but it is not enough by itself to prove that the traffic should always be direct-routed. BGP observations may include overseas PoPs, anycast, route leaks, collector bias, stale snapshots, or multi-origin prefixes.

For that reason, this repository separates three concepts:

1. Main rules: high-confidence direct-route rules used by normal clients.
2. RIR audit: registration country data from the five RIRs.
3. BGP origin audit: observed prefix-origin data matched against main and RIR ASN sets.

## Supported input format

`scripts/bgp_origin_audit.py` expects normalized text files in `upstream/bgp-origin/raw/*.txt`.

Supported line shapes include:

```text
1.0.1.0/24 4134
1.0.1.0 24 4134
2400:3200::/32 AS4134
1.0.1.0/24|4134_4809
```

The parser accepts single-origin and multi-origin ASN fields. Comments beginning with `#` are ignored. Private, loopback, link-local, and otherwise non-global prefixes are rejected from the audit result.

This script does not parse raw MRT files. MRT parsing should happen upstream with a dedicated BGP tool, and the normalized prefix-to-AS output should be committed or supplied to the manual workflow.

## Output files

The audit layer writes:

- `upstream/bgp-origin/prefixes-main-asn.txt`
- `upstream/bgp-origin/prefixes-rir-only-asn.txt`
- `upstream/bgp-origin/asns-main-seen.txt`
- `upstream/bgp-origin/asns-rir-only-seen.txt`
- `upstream/audit/bgp-origin-summary.json`
- `dist/registry/cn-bgp-origin.conf`
- `dist/registry/cn-bgp-rir-only-origin.conf`
- `dist/bgp-origin-audit-manifest.json`

`cn-bgp-origin.conf` contains prefixes originated by the main high-confidence ASN set. `cn-bgp-rir-only-origin.conf` contains prefixes whose origin ASN appears only in the RIR CN audit set. The second file is especially audit-only.

## Promotion rule

A BGP-origin prefix should not be promoted into the main rules unless there is additional evidence, such as:

- agreement with existing high-confidence IP sources;
- stable observation across multiple collectors or snapshots;
- explicit maintainer review;
- no match against high-risk cloud, CDN, or anycast exceptions.

The recommended workflow is to inspect `bgp-origin-summary.json`, then open an issue or pull request for any proposed promotion.
