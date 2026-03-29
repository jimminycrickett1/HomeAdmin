# AGENTS Instructions (Repository Scope)

## Mission and scope

- HomeAdmin is for defensive asset inventory and drift awareness in explicitly authorized home/lab environments.
- Keep changes conservative, deterministic, and auditable.

## Hard boundaries

- Do **not** add exploitation, offensive tradecraft, persistence, or remediation automation.
- Do **not** broaden discovery scope implicitly; require explicit configuration.

## Provenance requirements

- Persist source provenance for collected artifacts and transformed records.
- Preserve command metadata and hashable artifact outputs where applicable.
- Prefer reproducible transforms over heuristic side effects.

## Expected development workflow

1. Keep PRs small and focused on one objective.
2. Add or update tests for parsing, normalization, reconciliation, and drift logic as relevant.
3. Run local checks before commit.
4. Update README/docs when behavior, prerequisites, or limitations change.
5. Use clear commit messages describing intent and operational impact.
