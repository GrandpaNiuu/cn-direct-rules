# ADR 0003: Source lifecycle and safe retirement

## Status

Accepted

## Context

The repository needs broad daily coverage without inventing rules or treating temporary network failures as proof that a rule is invalid. A single monolithic refresh also prevents healthy sources from advancing when one provider is unavailable.

## Decision

Maintain a verified snapshot for each configured upstream and aggregate only parsed records from those snapshots. Refresh sources independently and reuse a source's last verified snapshot on failure.

For domains and ASNs, retain a missing rule until it has been absent from three observations on distinct Beijing calendar days where every configured source refreshed successfully. Re-running the updater on the same day or falling back for any source does not advance the counter. Reject any observation that would retire more than 1% or 1,000 rules. For CIDRs, compare normalized address-union coverage and reject a drop greater than 1%.

Publish per-source metadata, lifecycle state, and a deterministic update report alongside the canonical aggregate.

## Consequences

- Temporary outages and one-off upstream mistakes do not immediately delete working rules.
- Healthy sources can update while another source is unavailable.
- Removed rules remain for a short grace period, trading immediate cleanup for lower false-deletion risk.
- Source snapshots increase repository size but provide reproducibility and provenance.
- The repository does not claim that DNS or HTTP probing can prove whether a domain is permanently invalid.
