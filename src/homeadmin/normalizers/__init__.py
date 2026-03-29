"""Normalization helpers for discovery outputs."""

from __future__ import annotations

from collections.abc import Mapping


def normalize_mac(raw_mac: str | None) -> str | None:
    """Normalize a MAC address to lowercase colon-separated format."""
    if raw_mac is None:
        return None
    cleaned = raw_mac.strip().lower().replace("-", ":")
    if not cleaned:
        return None
    parts = [part.zfill(2) for part in cleaned.split(":") if part]
    if len(parts) != 6:
        return None
    return ":".join(parts)


def normalize_hostname(raw_hostname: str | None) -> str | None:
    """Normalize hostnames to lowercase and remove trailing dots."""
    if raw_hostname is None:
        return None
    cleaned = raw_hostname.strip().lower().rstrip(".")
    return cleaned or None


def normalize_observation(observation: Mapping[str, object]) -> dict[str, object]:
    """Normalize a generic discovery observation payload."""
    normalized = dict(observation)
    normalized["mac"] = normalize_mac(observation.get("mac") if "mac" in observation else None)
    normalized["hostname"] = normalize_hostname(
        observation.get("hostname") if "hostname" in observation else None
    )
    if "ip" in observation:
        normalized["ip"] = str(observation["ip"]).strip()
    return normalized
