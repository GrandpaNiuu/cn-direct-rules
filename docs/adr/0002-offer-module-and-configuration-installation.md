# Offer both module and full-configuration installation for Shadowrocket

Shadowrocket users have two distinct setup needs, so the repository publishes both a Standalone Complete Module and a Standalone Complete Configuration. The module is the recommended default for users who already have a working setup because it augments their configuration without replacing nodes, DNS, groups, or final policy. The full configuration is an explicit alternative for a clean setup or reset and warns users that it replaces the current configuration.

Both artifacts are rendered from the same Canonical Rule Model, use fixed `main/dist` Raw URLs, and are accepted by a closed HTTPS installation bridge. This keeps installation approachable without introducing a second hand-maintained rule set or an open redirect.
