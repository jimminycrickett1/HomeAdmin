"""Reconciliation workflow implementation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from homeadmin.storage.db import Storage


@dataclass(frozen=True, slots=True)
class ReconcileResult:
    """Outcome of a reconciliation run."""

    run_id: int
    run_uuid: str
    asset_count: int


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_discovery_assets(discovery_path: Path) -> list[dict[str, Any]]:
    """Load a discovery asset list from disk."""
    payload = json.loads(discovery_path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("Discovery payload must be a JSON list")
    assets: list[dict[str, Any]] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        uid = str(item.get("asset_uid") or item.get("mac_address") or item.get("ip_address") or "").strip()
        if not uid:
            continue
        item = dict(item)
        item["asset_uid"] = uid
        item.setdefault("sources", [])
        assets.append(item)
    return assets


def reconcile_assets(storage: Storage, assets: list[dict[str, Any]], *, run_uuid: str | None = None) -> ReconcileResult:
    """Persist reconciled asset snapshots and observations for a run."""
    started_at = _now_iso()
    resolved_run_uuid = run_uuid or str(uuid4())
    run_payload = {
        "run_uuid": resolved_run_uuid,
        "source_collector": "reconcile",
        "started_at": started_at,
        "finished_at": _now_iso(),
        "raw_artifact_path": None,
        "raw_artifact_hash": None,
        "confidence": 1.0,
        "status": "completed",
        "is_partial": 0,
    }

    run_id = storage.upsert_run(run_payload)

    for asset in assets:
        now = _now_iso()
        asset_payload = {
            "asset_uid": asset["asset_uid"],
            "mac_address": asset.get("mac_address"),
            "ip_address": asset.get("ip_address"),
            "hostname": asset.get("hostname"),
            "first_seen_at": now,
            "last_seen_at": now,
            "source_collector": "reconcile",
            "raw_artifact_path": None,
            "raw_artifact_hash": None,
            "confidence": float(asset.get("confidence", 1.0)),
            "status": str(asset.get("status", "active")),
            "is_active": 1,
        }
        asset_id = storage.upsert_asset(asset_payload)
        snapshot = {
            "asset_uid": asset["asset_uid"],
            "mac_address": asset.get("mac_address"),
            "ip_address": asset.get("ip_address"),
            "hostname": asset.get("hostname"),
            "status": asset.get("status", "active"),
            "sources": asset.get("sources", []),
            "source_observations": asset.get("source_observations", {}),
        }
        snapshot_json = json.dumps(snapshot, sort_keys=True)
        observation_payload = {
            "run_id": run_id,
            "collection_job_id": None,
            "asset_id": asset_id,
            "identity_id": None,
            "service_id": None,
            "observed_at": now,
            "observation_type": "asset_snapshot",
            "observation_key": asset["asset_uid"],
            "observation_value": snapshot_json,
            "source_collector": "reconcile",
            "raw_artifact_path": None,
            "raw_artifact_hash": sha256(snapshot_json.encode("utf-8")).hexdigest(),
            "confidence": float(asset.get("confidence", 1.0)),
            "status": "observed",
            "is_deleted": 0,
        }
        storage.upsert_observation(observation_payload)

    storage.connection.commit()
    return ReconcileResult(run_id=run_id, run_uuid=resolved_run_uuid, asset_count=len(assets))
