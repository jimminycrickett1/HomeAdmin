# HomeAdmin

HomeAdmin is a conservative home-network inventory CLI for collecting discovery output, normalizing records, reconciling identities, and classifying drift.

## Quickstart

## Storage strategy (M3)

- **Runtime backend for M3:** SQLite (`.homeadmin/homeadmin.db`) via `homeadmin.storage.db.Storage`.
- **PostgreSQL status:** deferred to a later milestone (target: M4+) behind the storage interface.
- SQLite remains the default for local development, CI, and current CLI workflows.

### 1) Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

### 2) Verify installation

Run both checks before continuing:

```bash
homeadmin --help
python -m homeadmin.cli --help
```

Expected result: both commands print CLI usage and exit successfully.

### 3) Configure tooling

HomeAdmin currently persists runtime state in a local SQLite database under `--state-dir` (default: `.homeadmin`).

Before running `discover`, you must set explicit scope controls:

```bash
export HOMEADMIN_ALLOWED_CIDRS='192.168.1.0/24'
export HOMEADMIN_ARP_SCAN_INTERFACE='eth0'
export HOMEADMIN_NMAP_INTERFACE='eth0'
# Optional tuning controls:
export HOMEADMIN_ARP_SCAN_MAX_SECONDS='120'
export HOMEADMIN_NMAP_MAX_RATE='100'
```

If scope values are missing or invalid, `homeadmin discover` exits non-zero.
If a collector fails, discovery persists a partial run and exits non-zero so operators can investigate safely.

External binaries expected in the runtime environment:

- `arp-scan` (required for collector execution)
- `nmap` (required for collector execution)

Confirm binaries are installed and accessible:

```bash
arp-scan --version
nmap --version
```

### 4) First workflow commands

Use the CLI in this sequence:

```bash
homeadmin discover
homeadmin reconcile
homeadmin baseline create
homeadmin drift
homeadmin report
```

Notes:
- `discover` now runs configured collectors (`arp-scan`, `nmap`) and writes `.homeadmin/discovery/latest.json` from normalized observations.
- `reconcile`, `baseline create`, `drift`, and `report` persist/read from `.homeadmin/homeadmin.db` and `.homeadmin/reports`.
- `plan generate` compiles recommendations into immutable, versioned execution plans (`plans`, `plan_steps`, `plan_approvals`).
- `plan show --id <id>` prints a persisted plan, and `plan diff --id <id>` compares it to the prior version.
- Plan lifecycle is stateful and audited: `draft -> proposed -> approved/rejected -> executed`.
- Approval is explicit owner action via `homeadmin plan approve --id <id> --approver <identity>` or `homeadmin plan reject --id <id> --approver <identity>`.
- For non-interactive runs, `plan approve`/`plan reject` accept `--approval-token` signed with `HOMEADMIN_APPROVAL_TOKEN_SECRET`.
- `homeadmin plan execute --id <id>` refuses execution unless the plan is currently approved and plan-hash verification passes.
- You can override the runtime directory with `--state-dir` for deterministic test runs.

## AI orchestration safety model

HomeAdmin includes an AI orchestration layer in `src/homeadmin/agent/` for producing recommendation-plan proposals.

### What it does

- Summarizes recommendation state (counts, priorities, assets).
- Proposes deterministic plan variants (`minimal-risk`, `balanced`, `coverage-first`).
- Emits explicit tradeoff justification per variant.
- Maps each recommendation to known execution method identifiers.

### Hard safety constraints

- **Read-only by default**: orchestration emits proposals only.
- **No direct command execution privileges**: orchestration does not run shell commands.
- **Structured output required**: output includes an `approval_workflow_payload` compatible with plan-generation workflow.
- **Mandatory human approval before apply**: apply-mode execution still requires explicit approval in plan state transitions.

### Audit and evaluation fixtures

Evaluation fixtures are provided under `tests/fixtures/agent/` to validate that orchestration output is:

- policy-compliant,
- deterministic enough for audit replay,
- traceable back to source evidence IDs.
