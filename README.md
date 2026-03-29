# HomeAdmin

HomeAdmin is a conservative home-network inventory CLI for collecting discovery output, normalizing records, reconciling identities, and classifying drift.

## Quickstart

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
- `discover` currently accepts optional JSON input (`--input`) and writes `.homeadmin/discovery/latest.json`.
- `reconcile`, `baseline create`, `drift`, and `report` persist/read from `.homeadmin/homeadmin.db` and `.homeadmin/reports`.
- You can override the runtime directory with `--state-dir` for deterministic test runs.
