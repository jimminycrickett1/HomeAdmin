"""Collector that runs nmap and captures structured artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from ipaddress import ip_network
from pathlib import Path
import json
import subprocess
from typing import Any


@dataclass(frozen=True, slots=True)
class ArtifactMetadata:
    """Provenance metadata for a collected artifact file."""

    label: str
    path: Path
    bytes_written: int
    sha256_hex: str


@dataclass(frozen=True, slots=True)
class CollectorRecord:
    """Structured result returned by a collector run."""

    collector_name: str
    run_id: str
    started_at: datetime
    finished_at: datetime
    interface: str
    allowed_cidrs: tuple[str, ...]
    scanned_cidrs: tuple[str, ...]
    command: tuple[str, ...]
    return_code: int
    artifacts: tuple[ArtifactMetadata, ...]


def _normalize_networks(raw_cidrs: list[str], *, label: str) -> list[str]:
    if not raw_cidrs:
        raise ValueError(f"{label} must contain at least one CIDR")
    normalized = []
    for value in raw_cidrs:
        normalized.append(str(ip_network(value, strict=False)))
    return normalized


def _validate_scope(config: dict[str, Any]) -> tuple[str, list[str], list[str]]:
    interface = str(config.get("interface", "")).strip()
    if not interface:
        raise ValueError("config.interface is required for nmap")

    allowed_cidrs = _normalize_networks(
        list(config.get("allowed_cidrs", [])), label="config.allowed_cidrs"
    )
    requested_raw = list(config.get("scan_cidrs", allowed_cidrs))
    requested_cidrs = _normalize_networks(requested_raw, label="config.scan_cidrs")

    allowed_networks = [ip_network(item, strict=False) for item in allowed_cidrs]
    for requested in requested_cidrs:
        requested_network = ip_network(requested, strict=False)
        if not any(
            requested_network.subnet_of(allowed_network) for allowed_network in allowed_networks
        ):
            raise ValueError(
                f"requested CIDR {requested} is not within config.allowed_cidrs"
            )

    return interface, allowed_cidrs, requested_cidrs


def _write_artifact(target: Path, content: bytes) -> ArtifactMetadata:
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    return ArtifactMetadata(
        label=target.name,
        path=target,
        bytes_written=len(content),
        sha256_hex=sha256(content).hexdigest(),
    )


def collect_nmap(config: dict[str, Any], *, run_id: str, run_root: Path) -> CollectorRecord:
    """Run nmap safely with explicit arguments from configuration."""

    interface, allowed_cidrs, scanned_cidrs = _validate_scope(config)
    binary = str(config.get("binary", "nmap"))
    extra_args = [str(value) for value in config.get("extra_args", [])]
    command = [binary, "-e", interface, *extra_args, *scanned_cidrs]

    started_at = datetime.now(UTC)
    completed = subprocess.run(
        command,
        capture_output=True,
        check=False,
    )
    finished_at = datetime.now(UTC)

    collector_dir = run_root / "artifacts" / run_id / "nmap"
    artifacts = [
        _write_artifact(collector_dir / "stdout.v1.txt", completed.stdout),
        _write_artifact(collector_dir / "stderr.v1.txt", completed.stderr),
    ]

    command_payload = {
        "command": command,
        "return_code": completed.returncode,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "interface": interface,
        "allowed_cidrs": allowed_cidrs,
        "scanned_cidrs": scanned_cidrs,
    }
    artifacts.append(
        _write_artifact(
            collector_dir / "command.v1.json",
            json.dumps(command_payload, indent=2, sort_keys=True).encode("utf-8"),
        )
    )

    return CollectorRecord(
        collector_name="nmap",
        run_id=run_id,
        started_at=started_at,
        finished_at=finished_at,
        interface=interface,
        allowed_cidrs=tuple(allowed_cidrs),
        scanned_cidrs=tuple(scanned_cidrs),
        command=tuple(command),
        return_code=completed.returncode,
        artifacts=tuple(artifacts),
    )
