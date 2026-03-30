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


def _normalize_mac(value: Any) -> str | None:
    raw = str(value or "").strip().lower()
    if not raw:
        return None
    candidate = raw.replace("-", ":")
    parts = candidate.split(":")
    if len(parts) == 6 and all(len(part) == 2 for part in parts):
        return candidate
    return None


def _identity_from_asset(asset: dict[str, Any]) -> tuple[str, str, str]:
    source_observations = asset.get("source_observations")
    macs: set[str] = set()
    if isinstance(source_observations, dict):
        for observation in source_observations.values():
            if not isinstance(observation, dict):
                continue
            mac = _normalize_mac(observation.get("mac_address") or observation.get("mac"))
            if mac:
                macs.add(mac)

    if not macs:
        direct_mac = _normalize_mac(asset.get("mac_address") or asset.get("mac"))
        if direct_mac:
            macs.add(direct_mac)

    if macs:
        selected = sorted(macs)[0]
        return (f"mac:{selected}", "mac", selected)

    hostname = str(asset.get("hostname") or "").strip().lower()
    if hostname:
        return (f"hostname:{hostname}", "hostname", hostname)

    ip_address = str(asset.get("ip_address") or asset.get("ip") or "").strip()
    if ip_address:
        return (f"ip:{ip_address}", "ip", ip_address)

    fallback = str(asset.get("asset_uid") or "").strip()
    if fallback:
        return (f"asset:{fallback}", "asset_uid", fallback)
    return ("unknown", "unknown", "unknown")


def _contradiction_details(asset: dict[str, Any]) -> str | None:
    source_observations = asset.get("source_observations")
    if not isinstance(source_observations, dict):
        return None

    macs = sorted(
        {
            mac
            for observation in source_observations.values()
            if isinstance(observation, dict)
            for mac in [_normalize_mac(observation.get("mac_address") or observation.get("mac"))]
            if mac
        }
    )
    if len(macs) > 1:
        return f"Conflicting source MAC evidence: {', '.join(macs)}"
    return None


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
        identity_uid, identity_type, identity_value = _identity_from_asset(asset)
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
        identity_id = storage.upsert_identity(
            {
                "identity_uid": identity_uid,
                "asset_id": asset_id,
                "identity_type": identity_type,
                "identity_value": identity_value,
                "first_seen_at": now,
                "last_seen_at": now,
                "source_collector": "reconcile",
                "raw_artifact_path": None,
                "raw_artifact_hash": None,
                "confidence": float(asset.get("confidence", 1.0)),
                "status": str(asset.get("status", "active")),
                "is_verified": 0,
            }
        )
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
            "identity_id": identity_id,
            "service_id": None,
            "observed_at": now,
            "observation_type": "asset_snapshot",
            "observation_key": identity_uid,
            "observation_value": snapshot_json,
            "source_collector": "reconcile",
            "raw_artifact_path": None,
            "raw_artifact_hash": sha256(snapshot_json.encode("utf-8")).hexdigest(),
            "confidence": float(asset.get("confidence", 1.0)),
            "status": "observed",
            "is_deleted": 0,
        }
        storage.upsert_observation(observation_payload)
        contradiction_detail = _contradiction_details(asset)
        if contradiction_detail:
            storage.upsert_discrepancy(
                {
                    "run_id": run_id,
                    "asset_id": asset_id,
                    "service_id": None,
                    "baseline_id": None,
                    "discrepancy_type": "reconcile_contradiction",
                    "fingerprint": sha256(contradiction_detail.encode("utf-8")).hexdigest(),
                    "details": contradiction_detail,
                    "detected_at": now,
                    "resolved_at": None,
                    "source_collector": "reconcile",
                    "raw_artifact_path": None,
                    "raw_artifact_hash": None,
                    "confidence": float(asset.get("confidence", 1.0)),
                    "status": "open",
                    "is_acknowledged": 0,
                }
            )

    storage.connection.commit()
    return ReconcileResult(run_id=run_id, run_uuid=resolved_run_uuid, asset_count=len(assets))
