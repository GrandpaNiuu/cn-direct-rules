# Source admission policy

The repository expands coverage only when a candidate has a traceable maintainer, machine-readable records, an explicit redistribution basis, recent maintenance, and either independent evidence or a useful non-duplicated slice.

## Admitted source roles

- V2Fly and felixonmars provide complementary structured and mainland-DNS domain evidence. High-risk platform-specific snapshots may be kept as audit-only sources with `contributes_to_aggregate: false` when their data is real but unsuitable for the main direct subscription.
- fernvenue, gaoyifan, and chnroutes2 provide independently generated APNIC/BGP routed coverage.
- APNIC delegated statistics provide an official registered-allocation audit, kept separate from routed geolocation claims.
- ASN-China provides a daily explicit `IP-ASN` snapshot.
- gaoyifan operator classifications provide optional operator slices rather than changing the conservative canonical aggregate.

## Candidates not merged

- Audit-only sources are refreshed and stored under `upstream/sources/`, but their values are removed from canonical aggregates and published client artifacts.
- Blackmatrix7 and ACL4SSR are broad downstream aggregators with substantial overlap. They remain useful comparison references, but importing them would weaken per-rule provenance and introduce additional copyleft obligations without enough independent coverage.
- 17mon/china_ip_list was not admitted because the repository does not declare a clear data license and its published rule data was not recently refreshed at the time of review.
- metowolf/iplist was not admitted because no explicit repository license was declared at the time of review.
- Other generated GeoIP/GeoSite repositories were not imported when their China data ultimately derived from sources already present here.

The list is deliberately revisitable: a rejected project can be admitted later if its provenance, license, maintenance, or independent coverage changes.
