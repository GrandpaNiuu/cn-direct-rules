# Mainland China Direct Rules

This context describes verified public-network rules that clients may assign to a direct-routing policy for mainland China.

## Language

**Canonical Rule Model**:
The normalized domain, public IP, ASN, and GeoIP fallback data from which every client artifact is generated.
_Avoid_: Master file, universal config

**Strict Coverage Profile**:
The default domain view that excludes known globally open suffixes whose wholesale direct routing carries excessive false-positive risk.
_Avoid_: Basic version, incomplete version

**Maximum Coverage Profile**:
The domain view that preserves all resolved mainland-oriented suffix coverage, including entries with a higher false-routing risk.
_Avoid_: New version, premium version

**Client Artifact**:
A syntax-specific rendering of the Canonical Rule Model for a supported client or import mechanism.
_Avoid_: Version, source list

**Standalone Complete Module**:
The independently installable Shadowrocket module containing the Maximum Coverage Profile, all verified public IPv4 and IPv6 ranges, ASN rules, and the GeoIP fallback. It augments an existing configuration instead of replacing it.
_Avoid_: Subscription, full configuration

**Standalone Complete Configuration**:
The remotely installable Shadowrocket configuration containing the Maximum Coverage Profile, all verified public IPv4 and IPv6 ranges, ASN rules, the GeoIP fallback, and a final proxy policy. It replaces the active configuration and is intended for a clean setup or reset.
_Avoid_: Module, rule fragment

**Private-network Rule**:
A rule for LAN, CGNAT, link-local, loopback, documentation, or otherwise non-public address space. It is intentionally outside this repository.
_Avoid_: China IP rule

**Verified Source Snapshot**:
The latest successfully downloaded, parsed, bounded, and hashed data for one configured upstream. A failed refresh keeps this snapshot and does not count as evidence that rules disappeared.
_Avoid_: Live truth, guaranteed-active list

**Lifecycle Grace**:
Three distinct successful source observations during which a missing domain or ASN is retained before it can be retired.
_Avoid_: Dead-site probe, immediate cleanup

**Retirement Circuit Breaker**:
The guard that rejects a refresh when its proposed removals or IP coverage loss exceed configured safety limits.
_Avoid_: Best-effort deletion

**Routed Coverage**:
Public prefixes observed through maintained BGP-derived sources and suitable for the canonical direct-routing model.
_Avoid_: Registered allocation, guaranteed physical location

**Registered Allocation Coverage**:
Public resources whose initial allocation or assignment country is CN in APNIC statistics. It is an audit and optional artifact, not proof of current physical location.
_Avoid_: GeoIP truth, routed coverage

**Operator Slice**:
An optional BGP-derived subset for one major mainland network operator. It may differ from the Canonical Rule Model and is published separately.
_Avoid_: Complete China IP list
