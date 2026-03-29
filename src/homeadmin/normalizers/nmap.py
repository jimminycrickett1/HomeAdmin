"""Normalizer for nmap text output to canonical observations."""

from __future__ import annotations

from datetime import datetime
import re

from homeadmin.models.observations import (
    DeviceObservation,
    ServiceEvidence,
    SourceProvenance,
)

_REPORT_FOR = re.compile(r"^Nmap scan report for (?P<target>.+)$")
_HOST_MAC = re.compile(r"^MAC Address:\s+(?P<mac>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})")
_SERVICE = re.compile(
    r"^(?P<port>\d+)\/(?P<proto>\w+)\s+(?P<state>\S+)\s+(?P<service>\S+)"
)
_TARGET_WITH_HOSTNAME = re.compile(
    r"^(?P<hostname>.+?)\s+\((?P<ip>(?:\d{1,3}\.){3}\d{1,3})\)$"
)


def _parse_target(target: str) -> tuple[str | None, str | None]:
    stripped = target.strip()
    if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", stripped):
        return stripped, None

    with_hostname = _TARGET_WITH_HOSTNAME.match(stripped)
    if with_hostname:
        return with_hostname.group("ip"), with_hostname.group("hostname")

    return None, stripped or None


def normalize_nmap_output(
    stdout: str,
    *,
    artifact_path: str,
    run_id: str,
    observed_at: datetime,
) -> list[DeviceObservation]:
    """Convert nmap text output into canonical observations."""

    provenance = SourceProvenance(
        collector="nmap",
        artifact_path=artifact_path,
        run_id=run_id,
        observed_at=observed_at,
    )

    observations: list[DeviceObservation] = []
    current_ip: str | None = None
    current_hostname: str | None = None
    current_mac: str | None = None
    current_services: list[ServiceEvidence] = []

    def flush_current() -> None:
        if not any((current_ip, current_hostname, current_mac, current_services)):
            return
        observations.append(
            DeviceObservation(
                provenance=provenance,
                ip=current_ip,
                mac=current_mac,
                hostname=current_hostname,
                services=tuple(current_services),
                first_seen_at=observed_at,
                last_seen_at=observed_at,
            )
        )

    for raw_line in stdout.splitlines():
        line = raw_line.rstrip()

        report_match = _REPORT_FOR.match(line)
        if report_match:
            flush_current()
            current_services = []
            current_mac = None
            current_ip, current_hostname = _parse_target(report_match.group("target"))
            continue

        mac_match = _HOST_MAC.match(line)
        if mac_match:
            current_mac = mac_match.group("mac").lower()
            continue

        service_match = _SERVICE.match(line)
        if service_match:
            current_services.append(
                ServiceEvidence(
                    port=int(service_match.group("port")),
                    protocol=service_match.group("proto"),
                    state=service_match.group("state"),
                    service=service_match.group("service"),
                )
            )

    flush_current()
    return observations
