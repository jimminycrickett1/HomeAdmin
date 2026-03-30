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


@dataclass(frozen=True, slots=True)
class IdentityEvidence:
    """Single confidence input used to score a reconciled identity."""

    evidence_type: str
    weight: float
    contribution: float
    detail: str


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


def _unknown_fingerprint(asset: dict[str, Any]) -> str:
    """Build a stable fingerprint for unknown backlog tracking."""
    explicit = str(asset.get("asset_uid") or "").strip()
    if explicit:
        return f"asset:{explicit}"

    mac = _normalize_mac(asset.get("mac_address") or asset.get("mac"))
    if mac:
        return f"mac:{mac}"

    hostname = str(asset.get("hostname") or "").strip().lower()
    if hostname:
        return f"hostname:{hostname}"

    ip_address = str(asset.get("ip_address") or asset.get("ip") or "").strip()
    if ip_address:
        return f"ip:{ip_address}"

    source_observations = asset.get("source_observations")
    if isinstance(source_observations, dict) and source_observations:
        normalized = json.dumps(source_observations, sort_keys=True)
        return f"observation:{sha256(normalized.encode('utf-8')).hexdigest()}"

    return "unknown:unidentified"


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


def _source_observations(asset: dict[str, Any]) -> dict[str, dict[str, Any]]:
    payload = asset.get("source_observations")
    if not isinstance(payload, dict):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for key, value in payload.items():
        if isinstance(value, dict):
            result[str(key)] = value
    return result


def _build_provenance(asset: dict[str, Any]) -> dict[str, Any]:
    source_observations = _source_observations(asset)
    raw_artifacts: list[dict[str, str]] = []
    seen_artifacts: set[tuple[str, str]] = set()

    for source_name, observation in source_observations.items():
        artifact_path = str(observation.get("raw_artifact_path") or observation.get("artifact_path") or "").strip()
        artifact_hash = str(observation.get("raw_artifact_hash") or observation.get("artifact_hash") or "").strip()
        if not artifact_path and not artifact_hash:
            continue
        key = (artifact_path, artifact_hash)
        if key in seen_artifacts:
            continue
        seen_artifacts.add(key)
        raw_artifacts.append(
            {
                "collector": source_name,
                "raw_artifact_path": artifact_path,
                "raw_artifact_hash": artifact_hash,
            }
        )

    return {
        "source_observation_keys": sorted(source_observations.keys()),
        "raw_artifacts": raw_artifacts,
    }


def _score_identity(asset: dict[str, Any], identity_type: str) -> tuple[float, list[IdentityEvidence]]:
    source_observations = _source_observations(asset)
    observations = list(source_observations.values())

    macs = [
        mac
        for observation in observations
        for mac in [_normalize_mac(observation.get("mac_address") or observation.get("mac"))]
        if mac
    ]
    unique_macs = sorted(set(macs))

    hostnames = [
        str(observation.get("hostname") or "").strip().lower()
        for observation in observations
        if str(observation.get("hostname") or "").strip()
    ]
    unique_hostnames = sorted(set(hostnames))

    ips = [
        str(observation.get("ip_address") or observation.get("ip") or "").strip()
        for observation in observations
        if str(observation.get("ip_address") or observation.get("ip") or "").strip()
    ]
    unique_ips = sorted(set(ips))

    service_signature_counts: dict[str, int] = {}
    for observation in observations:
        services = observation.get("services")
        if not isinstance(services, list):
            continue
        for service in services:
            if not isinstance(service, dict):
                continue
            signature = (
                f"{service.get('port', '')}/"
                f"{service.get('protocol', 'tcp')}/"
                f"{service.get('service_name') or service.get('service') or ''}"
            )
            service_signature_counts[signature] = service_signature_counts.get(signature, 0) + 1

    evidence: list[IdentityEvidence] = []

    mac_match_contribution = 1.0 if len(unique_macs) == 1 and len(macs) >= 1 else 0.0
    if len(unique_macs) > 1:
        mac_match_contribution = 0.0
    evidence.append(
        IdentityEvidence(
            evidence_type="mac_match",
            weight=0.55,
            contribution=mac_match_contribution,
            detail=(
                f"unique_macs={len(unique_macs)} observed_macs={unique_macs or 'none'}"
            ),
        )
    )

    stable_hostname_contribution = 1.0 if len(unique_hostnames) == 1 and len(hostnames) >= 2 else 0.0
    evidence.append(
        IdentityEvidence(
            evidence_type="stable_hostname",
            weight=0.20,
            contribution=stable_hostname_contribution,
            detail=(
                f"unique_hostnames={len(unique_hostnames)} observed_hostnames={unique_hostnames or 'none'}"
            ),
        )
    )

    repeated_ip_contribution = 1.0 if len(unique_ips) == 1 and len(ips) >= 2 else 0.0
    evidence.append(
        IdentityEvidence(
            evidence_type="repeated_ip_history",
            weight=0.10,
            contribution=repeated_ip_contribution,
            detail=f"unique_ips={len(unique_ips)} observed_ip_count={len(ips)}",
        )
    )

    has_continuous_service = any(count >= 2 for count in service_signature_counts.values())
    evidence.append(
        IdentityEvidence(
            evidence_type="service_continuity",
            weight=0.10,
            contribution=1.0 if has_continuous_service else 0.0,
            detail=(
                "repeated_service_signatures="
                f"{sorted([key for key, count in service_signature_counts.items() if count >= 2]) or 'none'}"
            ),
        )
    )

    contradiction_penalty = 0.0
    if len(unique_macs) > 1:
        contradiction_penalty -= 0.30
    if len(unique_hostnames) > 1:
        contradiction_penalty -= 0.10
    if identity_type == "ip" and len(unique_ips) == 1:
        contradiction_penalty -= 0.20

    evidence.append(
        IdentityEvidence(
            evidence_type="contradiction_penalty",
            weight=1.0,
            contribution=contradiction_penalty,
            detail=(
                f"penalty={contradiction_penalty:.2f} mac_conflicts={len(unique_macs) > 1} "
                f"hostname_conflicts={len(unique_hostnames) > 1}"
            ),
        )
    )

    score = sum(item.weight * item.contribution for item in evidence)
    return (max(0.0, min(1.0, score)), evidence)


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
        inferred_status = str(asset.get("status", "active"))
        if not asset.get("mac_address") and not asset.get("hostname"):
            inferred_status = "unknown"
        confidence, evidence_trail = _score_identity(asset, identity_type)
        provenance = _build_provenance(asset)
        provenance_json = json.dumps(provenance, sort_keys=True)
        provenance_hash = sha256(provenance_json.encode("utf-8")).hexdigest()
        artifact_paths = [
            str(raw_artifact.get("raw_artifact_path"))
            for raw_artifact in provenance.get("raw_artifacts", [])
            if str(raw_artifact.get("raw_artifact_path") or "").strip()
        ]
        combined_artifact_path = ",".join(sorted(set(artifact_paths))) or None

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
            "status": inferred_status,
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
                "raw_artifact_path": combined_artifact_path,
                "raw_artifact_hash": provenance_hash,
                "confidence": confidence,
                "status": str(asset.get("status", "active")),
                "is_verified": 0,
            }
        )
        for evidence in evidence_trail:
            storage.upsert_identity_evidence(
                {
                    "identity_id": identity_id,
                    "run_id": run_id,
                    "evidence_type": evidence.evidence_type,
                    "weight": evidence.weight,
                    "contribution": evidence.contribution,
                    "score": evidence.weight * evidence.contribution,
                    "detail": evidence.detail,
                    "provenance": provenance_json,
                    "source_collector": "reconcile",
                    "raw_artifact_path": combined_artifact_path,
                    "raw_artifact_hash": provenance_hash,
                }
            )
        snapshot = {
            "asset_uid": asset["asset_uid"],
            "mac_address": asset.get("mac_address"),
            "ip_address": asset.get("ip_address"),
            "hostname": asset.get("hostname"),
            "status": inferred_status,
            "sources": asset.get("sources", []),
            "source_observations": asset.get("source_observations", {}),
            "provenance": provenance,
            "identity_confidence": confidence,
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
            "raw_artifact_path": combined_artifact_path,
            "raw_artifact_hash": sha256(snapshot_json.encode("utf-8")).hexdigest(),
            "confidence": confidence,
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
                    "raw_artifact_path": combined_artifact_path,
                    "raw_artifact_hash": provenance_hash,
                    "confidence": confidence,
                    "status": "open",
                    "is_acknowledged": 0,
                }
            )

    storage.connection.commit()
    return ReconcileResult(run_id=run_id, run_uuid=resolved_run_uuid, asset_count=len(assets))
