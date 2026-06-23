# Third-party notices

The aggregate files under `upstream/` are generated from the traceable source snapshots under `upstream/sources/`.

The IPv4 and IPv6 data include the CHN CIDR list maintained at <https://github.com/fernvenue/chn-cidr-list>.

That project states that its source data comes from BGP/ASN and APNIC and distributes its work under the BSD 3-Clause License. Copyright and license terms remain with their respective owners. See [`third_party/LICENSE-chn-cidr-list.txt`](third_party/LICENSE-chn-cidr-list.txt).

The normalized files `upstream/domain-*.txt` are derived from the `cn` list in <https://github.com/v2fly/domain-list-community>, distributed under the MIT License. Unsupported regular-expression entries are counted in `upstream/domain-metadata.json` but are not emitted because the target clients do not share one portable regex syntax. See [`third_party/LICENSE-domain-list-community.txt`](third_party/LICENSE-domain-list-community.txt).

The high-coverage domain suffix snapshot is derived from <https://github.com/felixonmars/dnsmasq-china-list>, distributed under the WTFPL Version 2. Only active `server=/domain/resolver` records are parsed; commented-out removals are ignored. See [`third_party/LICENSE-dnsmasq-china-list.txt`](third_party/LICENSE-dnsmasq-china-list.txt).

The independent BGP/operator IPv4 and IPv6 snapshots are derived from <https://github.com/gaoyifan/china-operator-ip>, distributed under the MIT License. See [`third_party/LICENSE-china-operator-ip.txt`](third_party/LICENSE-china-operator-ip.txt).

The daily China ASN snapshot is derived from <https://github.com/missuo/ASN-China>, distributed under the MIT License. See [`third_party/LICENSE-ASN-China.txt`](third_party/LICENSE-ASN-China.txt).
