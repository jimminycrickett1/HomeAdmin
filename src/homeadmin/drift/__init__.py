"""Drift classification helpers."""

from __future__ import annotations


def classify_drift(
    *,
    baseline_assets: list[dict[str, object]],
    observed_assets: list[dict[str, object]],
    network_visibility_complete: bool,
    scan_profile: str,
) -> list[dict[str, object]]:
    """Classify differences between baseline and current observations."""
    baseline_by_key = {item["identity_key"]: item for item in baseline_assets if "identity_key" in item}
    observed_by_key = {item["identity_key"]: item for item in observed_assets if "identity_key" in item}

    findings: list[dict[str, object]] = []

    for key, baseline in baseline_by_key.items():
        observed = observed_by_key.get(key)
        if observed is None:
            findings.append({"identity_key": key, "classification": "sleeping_device_or_offline"})
            continue

        baseline_ip = baseline.get("ip")
        observed_ip = observed.get("ip")
        if baseline_ip and observed_ip and baseline_ip != observed_ip:
            findings.append({"identity_key": key, "classification": "ip_churn"})

        if baseline.get("hostname") and observed.get("hostname") is None:
            findings.append({"identity_key": key, "classification": "identity_ambiguity"})

        if baseline.get("services") != observed.get("services"):
            findings.append({"identity_key": key, "classification": "service_drift"})

    for key in observed_by_key:
        if key not in baseline_by_key:
            findings.append({"identity_key": key, "classification": "new_asset"})

    if not network_visibility_complete:
        findings.append({"identity_key": "_global", "classification": "incomplete_network_visibility"})

    if scan_profile.lower() in {"safe", "low-intensity"}:
        findings.append({"identity_key": "_global", "classification": "scan_sensitivity"})

    return findings
"""Drift classification logic."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from typing import Any

from homeadmin.baseline import load_current_baseline_assets
from homeadmin.storage.db import Storage


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


def calculate_drift(storage: Storage) -> DriftResult:
    """Compare latest run to previous run, or baseline when previous run is unavailable."""
    latest_row = storage.connection.execute(
        "SELECT id FROM runs ORDER BY id DESC LIMIT 1"
    ).fetchone()
    if latest_row is None:
        raise RuntimeError("Cannot detect drift: no reconciled runs exist")

    latest_run_id = int(latest_row["id"])
    latest = _load_run_snapshots(storage, latest_run_id)

    prev_row = storage.connection.execute(
        "SELECT id FROM runs WHERE id < ? ORDER BY id DESC LIMIT 1",
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

    unresolved_unknowns = [
        asset
        for asset in latest.values()
        if str(asset.get("status", "")).lower() == "unknown"
        or (not asset.get("mac_address") and not asset.get("hostname"))
    ]

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
        generated_at=datetime.now(timezone.utc).isoformat(),
        current=current,
        new=new,
        missing=missing,
        unresolved_unknowns=unresolved_unknowns,
        source_contradictions=source_contradictions,
    )

    with storage.transaction():
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
                    "detected_at": datetime.now(timezone.utc).isoformat(),
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
