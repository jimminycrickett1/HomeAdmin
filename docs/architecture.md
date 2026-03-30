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

## AI orchestration layer (`src/homeadmin/agent/`)

HomeAdmin now includes a deterministic AI orchestration layer that prepares **proposal-only** outputs:

- **State summarization:** emits counts and covered asset IDs from recommendation inputs.
- **Plan variants:** emits three deterministic variants (`minimal-risk`, `balanced`, `coverage-first`).
- **Tradeoff justification:** each variant contains explicit tradeoff notes and evidence-linked rationale.
- **Execution method mapping:** each recommendation maps to known execution method identifiers; no shell commands are produced.

### Trust boundaries

- The orchestration layer is **read-only by default** and treats incoming recommendation payloads as immutable input.
- The layer has **no direct command execution privileges**; it cannot run apply actions.
- It must emit a **structured `approval_workflow_payload`** that can be consumed by the existing `homeadmin plan generate` workflow.
- Any apply-mode change still requires the existing lifecycle: `proposed -> approved -> executed`, with explicit human approval before apply.

### Failure modes

- **Policy envelope mismatch:** output is rejected if read-only defaults, no-exec constraints, or human-approval requirement are missing.
- **Non-deterministic ordering:** output is rejected if recommendation ordering is not stable for audit replay.
- **Missing traceability:** output is rejected when recommendations omit source evidence IDs or evidence is absent from the emitted catalog.
- **Unknown rule mapping:** unknown recommendation rules are mapped to a conservative `manual-investigation` execution method.
