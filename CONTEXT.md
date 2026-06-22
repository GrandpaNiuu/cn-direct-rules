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

**Private-network Rule**:
A rule for LAN, CGNAT, link-local, loopback, documentation, or otherwise non-public address space. It is intentionally outside this repository.
_Avoid_: China IP rule
