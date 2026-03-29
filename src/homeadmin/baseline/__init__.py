"""Baseline creation helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from typing import Any

from homeadmin.storage.db import Storage


@dataclass(frozen=True, slots=True)
class BaselineCreateResult:
    """Outcome of baseline creation."""

    baseline_version: str
    baseline_count: int


def create_baseline_snapshot(storage: Storage) -> BaselineCreateResult:
    """Snapshot the latest reconciled asset state into versioned baselines."""
    latest_run = storage.connection.execute(
        "SELECT id, run_uuid FROM runs ORDER BY id DESC LIMIT 1"
    ).fetchone()
    if latest_run is None:
        raise RuntimeError("Cannot create baseline: no runs exist yet")

    run_id = int(latest_run["id"])
    baseline_version = datetime.now(timezone.utc).strftime("baseline-%Y%m%dT%H%M%SZ")

    snapshots = storage.connection.execute(
        """
        SELECT o.observation_key AS asset_uid, o.observation_value, a.id AS asset_id
        FROM observations o
        JOIN assets a ON a.asset_uid = o.observation_key
        WHERE o.run_id = ? AND o.observation_type = 'asset_snapshot'
        """,
        (run_id,),
    ).fetchall()

    with storage.transaction() as conn:
        conn.execute("UPDATE baselines SET is_current = 0 WHERE is_current = 1")
        for row in snapshots:
            asset_uid = str(row["asset_uid"])
            observation_value = str(row["observation_value"] or "{}")
            fingerprint = hashlib.sha256(observation_value.encode("utf-8")).hexdigest()
            baseline_key = f"{baseline_version}:{asset_uid}"
            payload: dict[str, Any] = {
                "baseline_key": baseline_key,
                "asset_id": int(row["asset_id"]),
                "service_id": None,
                "expected_fingerprint": fingerprint,
                "expected_state": observation_value,
                "valid_from": datetime.now(timezone.utc).isoformat(),
                "valid_to": None,
                "source_collector": "baseline.create",
                "raw_artifact_path": None,
                "raw_artifact_hash": None,
                "confidence": 1.0,
                "status": "active",
                "is_current": 1,
            }
            storage.upsert_baseline(payload)

    return BaselineCreateResult(baseline_version=baseline_version, baseline_count=len(snapshots))


def load_current_baseline_assets(storage: Storage) -> dict[str, dict[str, Any]]:
    """Load assets represented by the current baseline version."""
    rows = storage.connection.execute(
        """
        SELECT a.asset_uid, b.expected_state
        FROM baselines b
        JOIN assets a ON a.id = b.asset_id
        WHERE b.is_current = 1
        """
    ).fetchall()
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        state = json.loads(str(row["expected_state"] or "{}"))
        result[str(row["asset_uid"])] = state
    return result
