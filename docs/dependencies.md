# Dependencies

## Runtime binaries

- `arp-scan` for ARP-layer local network discovery.
- `nmap` for host/service discovery under allowed scope.

## Python runtime

- Python 3.11+
- Package metadata and build tooling via `hatchling`.

## Data store

- PostgreSQL is the intended production store for workflow/state persistence.
- Keep database credentials in environment variables or secret stores (never hard-coded).
