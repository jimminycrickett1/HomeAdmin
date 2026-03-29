"""Configuration loading and scope validation contract tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from homeadmin.config import AppConfig, load_config, validate_discovery_scope


def test_load_config_returns_app_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HOMEADMIN_ALLOWED_CIDRS", raising=False)
    config = load_config()
    assert isinstance(config, AppConfig)


def test_load_config_reads_env_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOMEADMIN_ALLOWED_CIDRS", "192.168.1.0/24,10.0.0.0/24")
    monkeypatch.setenv("HOMEADMIN_ARP_SCAN_INTERFACE", "eth0")
    monkeypatch.setenv("HOMEADMIN_NMAP_INTERFACE", "eth0")

    config = load_config()

    assert config.allowed_cidrs == ("192.168.1.0/24", "10.0.0.0/24")
    assert config.arp_scan_interface == "eth0"
    assert config.nmap_interface == "eth0"


def test_load_config_reads_optional_json_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_file = tmp_path / "homeadmin.config.json"
    config_file.write_text(
        json.dumps(
            {
                "state_dir": str(tmp_path / "state"),
                "allowed_cidrs": ["192.168.1.0/24"],
                "arp_scan_interface": "eth0",
                "nmap_interface": "eth0",
                "arp_scan_max_seconds": 60,
                "nmap_max_rate": 50,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("HOMEADMIN_CONFIG_FILE", str(config_file))
    monkeypatch.delenv("HOMEADMIN_ALLOWED_CIDRS", raising=False)

    config = load_config()

    assert config.state_dir == tmp_path / "state"
    assert config.allowed_cidrs == ("192.168.1.0/24",)
    assert config.arp_scan_max_seconds == 60
    assert config.nmap_max_rate == 50


def test_validate_discovery_scope_rejects_missing_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HOMEADMIN_ALLOWED_CIDRS", raising=False)
    config = load_config()

    with pytest.raises(ValueError, match="allowed_cidrs"):
        validate_discovery_scope(config)
