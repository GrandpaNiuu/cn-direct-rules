# Third-party notices

The files `upstream/ipv4.txt` and `upstream/ipv6.txt` are derived from the CHN CIDR list maintained at <https://github.com/fernvenue/chn-cidr-list>.

That project states that its source data comes from BGP/ASN and APNIC and distributes its work under the BSD 3-Clause License. Copyright and license terms remain with their respective owners. See [`third_party/LICENSE-chn-cidr-list.txt`](third_party/LICENSE-chn-cidr-list.txt).

The normalized files `upstream/domain-*.txt` are derived from the `cn` list in <https://github.com/v2fly/domain-list-community>, distributed under the MIT License. Unsupported regular-expression entries are counted in `upstream/domain-metadata.json` but are not emitted because the target clients do not share one portable regex syntax. See [`third_party/LICENSE-domain-list-community.txt`](third_party/LICENSE-domain-list-community.txt).
