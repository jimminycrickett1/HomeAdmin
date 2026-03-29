"""Normalizer for arp-scan text output to canonical observations."""

from __future__ import annotations

from datetime import datetime
import re

from homeadmin.models.observations import DeviceObservation, SourceProvenance

_ARP_LINE = re.compile(
    r"^(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+"
    r"(?P<mac>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})"
    r"(?:\s+(?P<vendor>.+))?$"
)


def normalize_arp_scan_output(
    stdout: str,
    *,
    artifact_path: str,
    run_id: str,
    observed_at: datetime,
) -> list[DeviceObservation]:
    """Convert arp-scan text output into canonical observations."""

    provenance = SourceProvenance(
        collector="arp_scan",
        artifact_path=artifact_path,
        run_id=run_id,
        observed_at=observed_at,
    )

    observations: list[DeviceObservation] = []
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        match = _ARP_LINE.match(line)
        if not match:
            continue

        observations.append(
            DeviceObservation(
                provenance=provenance,
                ip=match.group("ip"),
                mac=match.group("mac").lower(),
                first_seen_at=observed_at,
                last_seen_at=observed_at,
            )
        )
    return observations
