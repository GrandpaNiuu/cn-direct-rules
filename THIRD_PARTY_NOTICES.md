# Third-party notices

The aggregate files under `upstream/` are generated from the traceable source snapshots under `upstream/sources/`.

The IPv4 and IPv6 data include the CHN CIDR list maintained at <https://github.com/fernvenue/chn-cidr-list>.

That project states that its source data comes from BGP/ASN and APNIC and distributes its work under the BSD 3-Clause License. Copyright and license terms remain with their respective owners. See [`third_party/LICENSE-chn-cidr-list.txt`](third_party/LICENSE-chn-cidr-list.txt).

The normalized files `upstream/domain-*.txt` are derived from the `cn` list in <https://github.com/v2fly/domain-list-community>, distributed under the MIT License. Unsupported regular-expression entries are counted in `upstream/domain-metadata.json` but are not emitted because the target clients do not share one portable regex syntax. See [`third_party/LICENSE-domain-list-community.txt`](third_party/LICENSE-domain-list-community.txt).

The high-coverage, Apple China, and Google China domain suffix snapshots are derived from <https://github.com/felixonmars/dnsmasq-china-list>, distributed under the WTFPL Version 2. Only active `server=/domain/resolver` records are parsed; commented-out removals are ignored. Google China is retained as an audit-only source snapshot and is excluded from canonical generated rules and client artifacts. See [`third_party/LICENSE-dnsmasq-china-list.txt`](third_party/LICENSE-dnsmasq-china-list.txt).

The independent BGP/operator IPv4 and IPv6 snapshots are derived from <https://github.com/gaoyifan/china-operator-ip>, distributed under the MIT License. See [`third_party/LICENSE-china-operator-ip.txt`](third_party/LICENSE-china-operator-ip.txt).

The daily China ASN snapshot is derived from <https://github.com/missuo/ASN-China>, distributed under the MIT License. See [`third_party/LICENSE-ASN-China.txt`](third_party/LICENSE-ASN-China.txt).

Additional hourly IPv4 BGP coverage is derived from <https://github.com/misakaio/chnroutes2>, copyright Misaka Network, Inc., distributed under CC BY-SA 4.0. Generated artifacts containing this data must preserve attribution and ShareAlike terms. See [`third_party/NOTICE-chnroutes2.txt`](third_party/NOTICE-chnroutes2.txt) and [`DATA_LICENSE.md`](DATA_LICENSE.md).

The official registered-allocation snapshot and coverage audit use APNIC's delegated statistics. These records identify initial allocation or assignment country and are not authoritative geolocation. See [`third_party/NOTICE-APNIC-statistics.txt`](third_party/NOTICE-APNIC-statistics.txt).

Operator-specific China Telecom, China Mobile, China Unicom, CERNET, and CSTNET snapshots are derived from the corresponding BGP classifications published by <https://github.com/gaoyifan/china-operator-ip> under the MIT License.
