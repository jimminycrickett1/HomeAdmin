# Privilege model

## Collection privileges

- `arp-scan` and `nmap` may require elevated network permissions depending on host OS.
- Run collection with the minimum privileges necessary for your scan profile.
- Restrict collection to explicit allowlisted CIDRs and interfaces.

## Database privileges

- Use a dedicated application role.
- Grant only required rights on HomeAdmin-owned schema objects.
- Avoid superuser roles for routine CLI workflows.

## Operational posture

- HomeAdmin supports inventory, baseline, and drift visibility.
- HomeAdmin does **not** perform exploitation, lateral movement, or remediation actions.
