# HomeAdmin

HomeAdmin is a conservative home-network inventory CLI for collecting discovery output, normalizing records, reconciling identities, and classifying drift.

## Quickstart

### 1) Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

### 2) Configure tooling

HomeAdmin expects explicit scope and external binaries in your runtime environment:

- `arp-scan` (required)
- `nmap` (required)

Confirm binaries are installed and accessible:

```bash
arp-scan --version
nmap --version
```

### 3) PostgreSQL setup

Create a dedicated database and least-privilege role:

```sql
CREATE ROLE homeadmin_app LOGIN PASSWORD 'change-me';
CREATE DATABASE homeadmin OWNER homeadmin_app;
```

Set your connection URL (example):

```bash
export HOMEADMIN_DATABASE_URL='postgresql://homeadmin_app:change-me@localhost:5432/homeadmin'
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

These commands currently provide scaffold output while the implementation is completed.
