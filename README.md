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
- You can override the runtime directory with `--state-dir` for deterministic test runs.
