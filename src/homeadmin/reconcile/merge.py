"""Reconciliation helpers for merging collector output."""

from __future__ import annotations

from homeadmin.normalizers import normalize_observation


def _identity_key(observation: dict[str, object]) -> str:
    mac = observation.get("mac")
    if isinstance(mac, str) and mac:
        return f"mac:{mac}"
    ip = observation.get("ip")
    if isinstance(ip, str) and ip:
        return f"ip:{ip}"
    return "unknown"


def merge_observations(
    arp_observations: list[dict[str, object]], nmap_observations: list[dict[str, object]]
) -> list[dict[str, object]]:
    """Merge arp-scan and nmap observations into unified assets."""
    merged: dict[str, dict[str, object]] = {}

    for source_name, observations in (("arp-scan", arp_observations), ("nmap", nmap_observations)):
        for raw_observation in observations:
            observation = normalize_observation(raw_observation)
            key = _identity_key(observation)
            record = merged.setdefault(
                key,
                {
                    "identity_key": key,
                    "ip": None,
                    "mac": None,
                    "hostname": None,
                    "services": [],
                    "sources": [],
                },
            )
            for field in ("ip", "mac", "hostname"):
                value = observation.get(field)
                if value:
                    record[field] = value
            if source_name == "nmap":
                service = observation.get("service")
                if isinstance(service, dict):
                    services = record.get("services")
                    if isinstance(services, list):
                        services.append(service)
            sources = record.get("sources")
            if isinstance(sources, list):
                sources.append(source_name)

    for record in merged.values():
        sources = record.get("sources")
        if isinstance(sources, list):
            unique_sources = sorted({str(source) for source in sources})
            record["sources"] = unique_sources

    return list(merged.values())
