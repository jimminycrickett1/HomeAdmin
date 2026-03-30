"""Drift classification workflow logic."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from typing import Any

from homeadmin.baseline import load_current_baseline_assets
from homeadmin.storage.db import Storage

UNKNOWN_BACKLOG_TYPE = "unknown_backlog"
CHRONIC_UNKNOWN_MIN_RECURRENCE = 3
CHRONIC_UNKNOWN_MIN_AGE_DAYS = 7


@dataclass(frozen=True, slots=True)
class DriftResult:
    """Drift classification output."""

    reference_type: str
    reference_run_id: int | None
    latest_run_id: int
    generated_at: str
    current: list[dict[str, Any]]
    new: list[dict[str, Any]]
    missing: list[dict[str, Any]]
    unresolved_unknowns: list[dict[str, Any]]
    source_contradictions: list[dict[str, Any]]


def _load_run_snapshots(storage: Storage, run_id: int) -> dict[str, dict[str, Any]]:
    rows = storage.connection.execute(
        """
        SELECT observation_key AS asset_uid, observation_value
        FROM observations
        WHERE run_id = ? AND observation_type = 'asset_snapshot'
        """,
        (run_id,),
    ).fetchall()
    snapshots: dict[str, dict[str, Any]] = {}
    for row in rows:
        snapshots[str(row["asset_uid"])] = json.loads(str(row["observation_value"] or "{}"))
    return snapshots


def _find_source_contradictions(asset: dict[str, Any]) -> list[str]:
    source_observations = asset.get("source_observations")
    if not isinstance(source_observations, dict):
        return []
    ips = {
        str(payload.get("ip_address"))
        for payload in source_observations.values()
        if isinstance(payload, dict) and payload.get("ip_address")
    }
    hostnames = {
        str(payload.get("hostname"))
        for payload in source_observations.values()
        if isinstance(payload, dict) and payload.get("hostname")
    }
    contradictions: list[str] = []
    if len(ips) > 1:
        contradictions.append("conflicting_ip_addresses")
    if len(hostnames) > 1:
        contradictions.append("conflicting_hostnames")
    return contradictions


def _is_unknown_asset(asset: dict[str, Any]) -> bool:
    return str(asset.get("status", "")).lower() == "unknown" or (
        not asset.get("mac_address") and not asset.get("hostname")
    )


def _unknown_fingerprint(asset: dict[str, Any]) -> str:
    return str(asset.get("unknown_fingerprint") or asset.get("asset_uid") or "unknown")


def _parse_iso8601(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _unknown_history(storage: Storage, fingerprint: str) -> dict[str, Any]:
    row = storage.connection.execute(
        """
        SELECT
          MIN(detected_at) AS first_detected_at,
          MAX(detected_at) AS last_detected_at,
          COUNT(DISTINCT run_id) AS recurrence_count
        FROM discrepancies
        WHERE discrepancy_type = ?
          AND fingerprint = ?
        """,
        (UNKNOWN_BACKLOG_TYPE, fingerprint),
    ).fetchone()
    recurrence_count = int(row["recurrence_count"] or 0)
    return {
        "first_detected_at": str(row["first_detected_at"]) if row["first_detected_at"] else None,
        "last_detected_at": str(row["last_detected_at"]) if row["last_detected_at"] else None,
        "recurrence_count": recurrence_count,
    }


def _classify_unknown(history: dict[str, Any], *, now: datetime) -> dict[str, Any]:
    recurrence_count = int(history["recurrence_count"]) + 1
    first_detected_at = history["first_detected_at"] or now.isoformat()
    first_detected_dt = _parse_iso8601(first_detected_at)
    age_days = max((now - first_detected_dt).days, 0)

    classification = "new_unknown"
    priority = "low"
    if recurrence_count >= CHRONIC_UNKNOWN_MIN_RECURRENCE or age_days >= CHRONIC_UNKNOWN_MIN_AGE_DAYS:
        classification = "chronic_unknown"
        priority = "high"
    elif recurrence_count >= 2:
        priority = "medium"

    return {
        "classification": classification,
        "priority": priority,
        "age_days": age_days,
        "recurrence_count": recurrence_count,
        "first_detected_at": first_detected_at,
        "last_detected_at": now.isoformat(),
    }


def _resolve_no_longer_unknown(storage: Storage, latest_run_id: int, unresolved_fingerprints: set[str], now_iso: str) -> None:
    rows = storage.connection.execute(
        """
        SELECT id, fingerprint
        FROM discrepancies
        WHERE discrepancy_type = ?
          AND status IN ('open', 'escalated')
        """,
        (UNKNOWN_BACKLOG_TYPE,),
    ).fetchall()
    for row in rows:
        discrepancy_id = int(row["id"])
        fingerprint = str(row["fingerprint"] or "")
        if not fingerprint or fingerprint in unresolved_fingerprints:
            continue
        storage.connection.execute(
            """
            UPDATE discrepancies
            SET status = 'resolved',
                resolved_at = ?,
                run_id = ?
            WHERE id = ?
            """,
            (now_iso, latest_run_id, discrepancy_id),
        )


def calculate_drift(storage: Storage) -> DriftResult:
    """Compare latest run to previous run, or baseline when previous run is unavailable."""
    latest_row = storage.connection.execute(
        """
        SELECT id FROM runs
        WHERE source_collector = 'reconcile'
        ORDER BY id DESC
        LIMIT 1
        """
    ).fetchone()
    if latest_row is None:
        raise RuntimeError("Cannot detect drift: no reconciled runs exist")

    latest_run_id = int(latest_row["id"])
    latest = _load_run_snapshots(storage, latest_run_id)

    prev_row = storage.connection.execute(
        """
        SELECT id FROM runs
        WHERE source_collector = 'reconcile' AND id < ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (latest_run_id,),
    ).fetchone()

    if prev_row is not None:
        reference_type = "previous_run"
        reference_run_id = int(prev_row["id"])
        reference = _load_run_snapshots(storage, reference_run_id)
    else:
        reference_type = "baseline"
        reference_run_id = None
        reference = load_current_baseline_assets(storage)

    latest_ids = set(latest.keys())
    reference_ids = set(reference.keys())

    current = [latest[asset_uid] for asset_uid in sorted(latest_ids & reference_ids)]
    new = [latest[asset_uid] for asset_uid in sorted(latest_ids - reference_ids)]
    missing = [reference[asset_uid] for asset_uid in sorted(reference_ids - latest_ids)]

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    unresolved_unknowns: list[dict[str, Any]] = []
    unresolved_fingerprints: set[str] = set()
    for asset in latest.values():
        if not _is_unknown_asset(asset):
            continue
        fingerprint = _unknown_fingerprint(asset)
        history = _unknown_history(storage, fingerprint)
        classification = _classify_unknown(history, now=now)
        enriched = dict(asset)
        enriched.update(classification)
        enriched["unknown_fingerprint"] = fingerprint
        unresolved_unknowns.append(enriched)
        unresolved_fingerprints.add(fingerprint)

    source_contradictions: list[dict[str, Any]] = []
    for asset in latest.values():
        contradictions = _find_source_contradictions(asset)
        if contradictions:
            enriched = dict(asset)
            enriched["contradictions"] = contradictions
            source_contradictions.append(enriched)

    result = DriftResult(
        reference_type=reference_type,
        reference_run_id=reference_run_id,
        latest_run_id=latest_run_id,
        generated_at=now_iso,
        current=current,
        new=new,
        missing=missing,
        unresolved_unknowns=sorted(
            unresolved_unknowns,
            key=lambda item: (
                0 if item.get("priority") == "high" else (1 if item.get("priority") == "medium" else 2),
                -int(item.get("recurrence_count", 0)),
                -int(item.get("age_days", 0)),
                str(item.get("asset_uid", "")),
            ),
        ),
        source_contradictions=source_contradictions,
    )

    with storage.transaction():
        _resolve_no_longer_unknown(storage, latest_run_id, unresolved_fingerprints, now_iso)

        for asset in unresolved_unknowns:
            status = "escalated" if asset["classification"] == "chronic_unknown" else "open"
            storage.upsert_discrepancy(
                {
                    "run_id": latest_run_id,
                    "asset_id": None,
                    "service_id": None,
                    "baseline_id": None,
                    "discrepancy_type": UNKNOWN_BACKLOG_TYPE,
                    "fingerprint": str(asset.get("unknown_fingerprint", "unknown")),
                    "details": json.dumps(asset, sort_keys=True),
                    "detected_at": now_iso,
                    "resolved_at": None,
                    "source_collector": "drift",
                    "raw_artifact_path": None,
                    "raw_artifact_hash": None,
                    "confidence": 1.0,
                    "status": status,
                    "is_acknowledged": 0,
                }
            )

        for asset in source_contradictions:
            storage.upsert_discrepancy(
                {
                    "run_id": latest_run_id,
                    "asset_id": None,
                    "service_id": None,
                    "baseline_id": None,
                    "discrepancy_type": "source_contradiction",
                    "fingerprint": str(asset.get("asset_uid", "unknown")),
                    "details": json.dumps(asset, sort_keys=True),
                    "detected_at": now_iso,
                    "resolved_at": None,
                    "source_collector": "drift",
                    "raw_artifact_path": None,
                    "raw_artifact_hash": None,
                    "confidence": 1.0,
                    "status": "open",
                    "is_acknowledged": 0,
                }
            )

    return result


def drift_to_dict(result: DriftResult) -> dict[str, Any]:
    """Convert drift result to a JSON-safe dictionary."""
    return asdict(result)
