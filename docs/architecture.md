# Architecture

## High-level flow

1. **Collect**: collector adapters run `arp-scan` and `nmap` inside explicitly allowed CIDR scope.
2. **Parse + Normalize**: raw collector output is parsed into typed records and normalized (MAC/hostname formatting, consistent keys).
3. **Reconcile**: records from multiple collectors are merged into a single asset-centric view with provenance.
4. **Persist**: normalized observations and derived entities are stored for comparison against baseline.
5. **Classify drift**: current observations are compared to baseline and tagged with deterministic drift categories.

## Design principles

- Conservative scope validation for all active collection.
- Provenance-first artifacts (command line, stdout, stderr, hashes).
- Deterministic transforms for repeatable runs.
- Separation between collection, normalization, merge, and drift logic.
