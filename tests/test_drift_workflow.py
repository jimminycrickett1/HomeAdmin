"""Drift workflow behavioral contracts."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

from homeadmin.drift.workflow import calculate_drift
from homeadmin.storage import Storage


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _insert_run(storage: Storage, run_uuid: str) -> int:
    return storage.upsert_run(
        {
            "run_uuid": run_uuid,
            "source_collector": "reconcile",
            "started_at": _now_iso(),
            "finished_at": _now_iso(),
            "raw_artifact_path": None,
            "raw_artifact_hash": None,
            "confidence": 1.0,
            "status": "completed",
            "is_partial": 0,
        }
    )


def _insert_discovery_run(storage: Storage, run_uuid: str) -> int:
    return storage.upsert_run(
        {
            "run_uuid": run_uuid,
            "source_collector": "discover",
            "started_at": _now_iso(),
            "finished_at": _now_iso(),
            "raw_artifact_path": None,
            "raw_artifact_hash": None,
            "confidence": 1.0,
            "status": "completed",
            "is_partial": 0,
        }
    )


def _insert_snapshot(storage: Storage, run_id: int, asset_uid: str, payload: dict[str, object]) -> None:
    storage.upsert_observation(
        {
            "run_id": run_id,
            "collection_job_id": None,
            "asset_id": None,
            "identity_id": None,
            "service_id": None,
            "observed_at": _now_iso(),
            "observation_type": "asset_snapshot",
            "observation_key": asset_uid,
            "observation_value": json.dumps(payload, sort_keys=True),
            "source_collector": "reconcile",
            "raw_artifact_path": None,
            "raw_artifact_hash": None,
            "confidence": 1.0,
            "status": "observed",
            "is_deleted": 0,
        }
    )


def test_drift_partitions_are_disjoint_and_complete(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "state.db")
    storage.initialize()

    first_run = _insert_run(storage, "run-1")
    _insert_snapshot(
        storage,
        first_run,
        "asset-a",
        {"asset_uid": "asset-a", "ip_address": "192.168.1.10", "hostname": "a.local", "status": "active"},
    )
    _insert_snapshot(
        storage,
        first_run,
        "asset-b",
        {"asset_uid": "asset-b", "ip_address": "192.168.1.11", "hostname": "b.local", "status": "active"},
    )

    second_run = _insert_run(storage, "run-2")
    _insert_snapshot(
        storage,
        second_run,
        "asset-a",
        {"asset_uid": "asset-a", "ip_address": "192.168.1.10", "hostname": "a.local", "status": "active"},
    )
    _insert_snapshot(
        storage,
        second_run,
        "asset-c",
        {"asset_uid": "asset-c", "ip_address": "192.168.1.12", "hostname": "c.local", "status": "active"},
    )

    storage.connection.commit()
    result = calculate_drift(storage)

    current = {item["asset_uid"] for item in result.current}
    new = {item["asset_uid"] for item in result.new}
    missing = {item["asset_uid"] for item in result.missing}

    assert current == {"asset-a"}
    assert new == {"asset-c"}
    assert missing == {"asset-b"}
    assert current.isdisjoint(new)
    assert current.isdisjoint(missing)
    assert new.isdisjoint(missing)


def test_drift_discrepancy_persistence_is_idempotent(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "state.db")
    storage.initialize()

    run_id = _insert_run(storage, "run-contradiction")
    _insert_snapshot(
        storage,
        run_id,
        "asset-z",
        {
            "asset_uid": "asset-z",
            "ip_address": "192.168.1.50",
            "hostname": "z.local",
            "status": "active",
            "source_observations": {
                "arp_scan": {"ip_address": "192.168.1.50", "hostname": "z.local"},
                "nmap": {"ip_address": "192.168.1.99", "hostname": "z.local"},
            },
        },
    )

    storage.connection.commit()
    first = calculate_drift(storage)
    second = calculate_drift(storage)

    assert len(first.source_contradictions) == 1
    assert len(second.source_contradictions) == 1

    count = storage.connection.execute(
        "SELECT COUNT(*) AS count FROM discrepancies WHERE discrepancy_type = 'source_contradiction'"
    ).fetchone()["count"]
    assert int(count) == 1


def test_drift_ignores_discovery_runs_for_latest_and_reference(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "state.db")
    storage.initialize()

    reconcile_1 = _insert_run(storage, "reconcile-1")
    _insert_snapshot(
        storage,
        reconcile_1,
        "asset-a",
        {"asset_uid": "asset-a", "ip_address": "192.168.1.10", "hostname": "a.local", "status": "active"},
    )

    _insert_discovery_run(storage, "discover-between")

    reconcile_2 = _insert_run(storage, "reconcile-2")
    _insert_snapshot(
        storage,
        reconcile_2,
        "asset-a",
        {"asset_uid": "asset-a", "ip_address": "192.168.1.10", "hostname": "a.local", "status": "active"},
    )
    _insert_snapshot(
        storage,
        reconcile_2,
        "asset-b",
        {"asset_uid": "asset-b", "ip_address": "192.168.1.11", "hostname": "b.local", "status": "active"},
    )

    _insert_discovery_run(storage, "discover-latest")

    storage.connection.commit()
    result = calculate_drift(storage)

    assert result.latest_run_id == reconcile_2
    assert result.reference_run_id == reconcile_1
    assert {item["asset_uid"] for item in result.current} == {"asset-a"}
    assert {item["asset_uid"] for item in result.new} == {"asset-b"}
    assert result.missing == []
