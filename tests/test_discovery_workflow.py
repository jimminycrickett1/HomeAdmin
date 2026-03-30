"""Discovery workflow integration contracts."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

from homeadmin.collectors.arp_scan import ArtifactMetadata as ArpArtifact
from homeadmin.collectors.arp_scan import CollectorRecord as ArpRecord
from homeadmin.collectors.nmap import ArtifactMetadata as NmapArtifact
from homeadmin.collectors.nmap import CollectorRecord as NmapRecord
from homeadmin.config import AppConfig
from homeadmin.discovery.workflow import run_discovery
from homeadmin.storage import Storage


def _artifact(path: Path, content: bytes) -> ArpArtifact:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return ArpArtifact(
        label=path.name,
        path=path,
        bytes_written=len(content),
        sha256_hex="h" + path.name,
    )


def _base_config(tmp_path: Path) -> AppConfig:
    return AppConfig(
        state_dir=tmp_path,
        allowed_cidrs=("192.168.1.0/24",),
        arp_scan_interface="eth0",
        nmap_interface="eth0",
        arp_scan_max_seconds=120,
        nmap_max_rate=100,
    )


def test_run_discovery_persists_jobs_observations_and_assets(tmp_path: Path, monkeypatch) -> None:
    now = datetime.now(timezone.utc)

    def fake_arp(config, *, run_id: str, run_root: Path):
        collector_dir = run_root / "artifacts" / run_id / "arp_scan"
        stdout = _artifact(collector_dir / "stdout.v1.txt", b"192.168.1.10\taa:bb:cc:dd:ee:ff\tAcme\n")
        stderr = _artifact(collector_dir / "stderr.v1.txt", b"")
        command = _artifact(collector_dir / "command.v1.json", b"{}")
        return ArpRecord(
            collector_name="arp_scan",
            run_id=run_id,
            started_at=now,
            finished_at=now,
            interface="eth0",
            allowed_cidrs=("192.168.1.0/24",),
            scanned_cidrs=("192.168.1.0/24",),
            command=("arp-scan",),
            return_code=0,
            artifacts=(stdout, stderr, command),
        )

    def fake_nmap(config, *, run_id: str, run_root: Path):
        collector_dir = run_root / "artifacts" / run_id / "nmap"
        stdout = _artifact(
            collector_dir / "stdout.v1.txt",
            (
                b"Host: 192.168.1.10 ()\tPorts: 22/open/tcp//ssh///\n"
                b"Host: 192.168.1.20 ()\tPorts: 80/open/tcp//http///\n"
            ),
        )
        stderr = _artifact(collector_dir / "stderr.v1.txt", b"")
        command = _artifact(collector_dir / "command.v1.json", b"{}")
        return NmapRecord(
            collector_name="nmap",
            run_id=run_id,
            started_at=now,
            finished_at=now,
            interface="eth0",
            allowed_cidrs=("192.168.1.0/24",),
            scanned_cidrs=("192.168.1.0/24",),
            command=("nmap",),
            return_code=0,
            artifacts=(stdout, stderr, command),
        )

    monkeypatch.setattr("homeadmin.discovery.workflow.collect_arp_scan", fake_arp)
    monkeypatch.setattr("homeadmin.discovery.workflow.collect_nmap", fake_nmap)

    storage = Storage(tmp_path / "homeadmin.db")
    storage.initialize()

    result = run_discovery(_base_config(tmp_path), storage, state_dir=tmp_path)

    assert result.collection_jobs == 2
    assert result.observation_count == 3
    assert result.asset_count == 2
    assert result.is_partial is False
    assert result.failed_collectors == ()
    assert result.discovery_path.exists()

    assets = json.loads(result.discovery_path.read_text(encoding="utf-8"))
    assert [asset["asset_uid"] for asset in assets] == ["192.168.1.20", "aa:bb:cc:dd:ee:ff"]

    job_count = storage.connection.execute("SELECT COUNT(*) AS count FROM collection_jobs").fetchone()["count"]
    assert int(job_count) == 2

    rows = storage.connection.execute(
        "SELECT asset_id, raw_artifact_path, raw_artifact_hash FROM observations WHERE run_id = ?",
        (result.run_id,),
    ).fetchall()
    assert len(rows) == 3
    assert all(row["asset_id"] is not None for row in rows)
    assert all(row["raw_artifact_path"] for row in rows)
    assert all(row["raw_artifact_hash"] for row in rows)
    asset_count = storage.connection.execute("SELECT COUNT(*) AS count FROM assets").fetchone()["count"]
    assert int(asset_count) == 2


def test_run_discovery_marks_partial_when_collector_fails(tmp_path: Path, monkeypatch) -> None:
    now = datetime.now(timezone.utc)

    def fake_arp(config, *, run_id: str, run_root: Path):
        collector_dir = run_root / "artifacts" / run_id / "arp_scan"
        stdout = _artifact(collector_dir / "stdout.v1.txt", b"192.168.1.10\taa:bb:cc:dd:ee:ff\tAcme\n")
        stderr = _artifact(collector_dir / "stderr.v1.txt", b"")
        command = _artifact(collector_dir / "command.v1.json", b"{}")
        return ArpRecord(
            collector_name="arp_scan",
            run_id=run_id,
            started_at=now,
            finished_at=now,
            interface="eth0",
            allowed_cidrs=("192.168.1.0/24",),
            scanned_cidrs=("192.168.1.0/24",),
            command=("arp-scan",),
            return_code=0,
            artifacts=(stdout, stderr, command),
        )

    def failing_nmap(config, *, run_id: str, run_root: Path):
        collector_dir = run_root / "artifacts" / run_id / "nmap"
        stdout = _artifact(collector_dir / "stdout.v1.txt", b"")
        stderr = _artifact(collector_dir / "stderr.v1.txt", b"permission denied")
        command = _artifact(collector_dir / "command.v1.json", b"{}")
        return NmapRecord(
            collector_name="nmap",
            run_id=run_id,
            started_at=now,
            finished_at=now,
            interface="eth0",
            allowed_cidrs=("192.168.1.0/24",),
            scanned_cidrs=("192.168.1.0/24",),
            command=("nmap",),
            return_code=1,
            artifacts=(stdout, stderr, command),
        )

    monkeypatch.setattr("homeadmin.discovery.workflow.collect_arp_scan", fake_arp)
    monkeypatch.setattr("homeadmin.discovery.workflow.collect_nmap", failing_nmap)

    storage = Storage(tmp_path / "homeadmin.db")
    storage.initialize()

    result = run_discovery(_base_config(tmp_path), storage, state_dir=tmp_path)

    assert result.is_partial is True
    assert result.failed_collectors == ("nmap",)
    assert result.observation_count == 1
    assert result.asset_count == 1

    run_row = storage.connection.execute(
        "SELECT status, is_partial FROM runs WHERE id = ?",
        (result.run_id,),
    ).fetchone()
    assert run_row is not None
    assert run_row["status"] == "partial"
    assert int(run_row["is_partial"]) == 1
    observation_row = storage.connection.execute(
        "SELECT asset_id FROM observations WHERE run_id = ? LIMIT 1",
        (result.run_id,),
    ).fetchone()
    assert observation_row is not None
    assert observation_row["asset_id"] is not None
