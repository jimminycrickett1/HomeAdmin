"""Configuration models and loading helpers."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_network
import json
import os
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class AppConfig:
    """Application-level configuration."""

    state_dir: Path
    allowed_cidrs: tuple[str, ...]
    arp_scan_interface: str | None
    nmap_interface: str | None
    arp_scan_max_seconds: int
    nmap_max_rate: int


def _load_optional_file_config() -> dict[str, Any]:
    config_file = os.environ.get("HOMEADMIN_CONFIG_FILE", "").strip()
    if not config_file:
        return {}

    payload = json.loads(Path(config_file).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("HOMEADMIN_CONFIG_FILE must point to a JSON object")
    return payload


def _list_str(value: Any) -> tuple[str, ...]:
    if value is None:
        return tuple()
    if not isinstance(value, list):
        raise ValueError("allowed_cidrs must be a list of CIDR strings")
    return tuple(str(item).strip() for item in value if str(item).strip())


def _positive_int(value: Any, *, default: int, label: str) -> int:
    if value in (None, ""):
        return default
    parsed = int(value)
    if parsed <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return parsed


def load_config() -> AppConfig:
    """Load the HomeAdmin configuration from env and optional JSON file."""
    file_config = _load_optional_file_config()

    state_dir_raw = os.environ.get("HOMEADMIN_STATE_DIR") or file_config.get("state_dir") or ".homeadmin"

    allowed_cidrs = _list_str(
        os.environ.get("HOMEADMIN_ALLOWED_CIDRS", "").split(",")
        if os.environ.get("HOMEADMIN_ALLOWED_CIDRS", "").strip()
        else file_config.get("allowed_cidrs")
    )

    arp_interface = os.environ.get("HOMEADMIN_ARP_SCAN_INTERFACE") or file_config.get("arp_scan_interface")
    nmap_interface = os.environ.get("HOMEADMIN_NMAP_INTERFACE") or file_config.get("nmap_interface")

    return AppConfig(
        state_dir=Path(str(state_dir_raw)),
        allowed_cidrs=allowed_cidrs,
        arp_scan_interface=str(arp_interface).strip() or None,
        nmap_interface=str(nmap_interface).strip() or None,
        arp_scan_max_seconds=_positive_int(
            os.environ.get("HOMEADMIN_ARP_SCAN_MAX_SECONDS") or file_config.get("arp_scan_max_seconds"),
            default=120,
            label="arp_scan_max_seconds",
        ),
        nmap_max_rate=_positive_int(
            os.environ.get("HOMEADMIN_NMAP_MAX_RATE") or file_config.get("nmap_max_rate"),
            default=100,
            label="nmap_max_rate",
        ),
    )


def validate_discovery_scope(config: AppConfig) -> None:
    """Validate explicit discovery scope requirements before any collection."""
    if not config.allowed_cidrs:
        raise ValueError("Discovery scope requires non-empty allowed_cidrs")

    for cidr in config.allowed_cidrs:
        ip_network(cidr, strict=False)

    if not config.arp_scan_interface:
        raise ValueError("Discovery scope requires arp_scan_interface")

    if not config.nmap_interface:
        raise ValueError("Discovery scope requires nmap_interface")

    if config.arp_scan_max_seconds <= 0:
        raise ValueError("arp_scan_max_seconds must be positive")

    if config.nmap_max_rate <= 0:
        raise ValueError("nmap_max_rate must be positive")
