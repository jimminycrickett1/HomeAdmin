"""Reconciliation workflow implementation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from homeadmin.models.observations import DeviceObservation, ServiceEvidence, SourceProvenance
from homeadmin.reconcile.identity import reconcile_observations
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


def _service_evidence_from_payload(payload: dict[str, Any]) -> tuple[ServiceEvidence, ...]:
    if isinstance(payload.get("service"), dict):
        service = payload["service"]
        return (
            ServiceEvidence(
                port=int(service.get("port", 0)),
                protocol=str(service.get("protocol", "tcp")),
                state=str(service.get("state")) if service.get("state") is not None else None,
                service=str(service.get("service") or service.get("service_name"))
                if service.get("service") or service.get("service_name")
                else None,
            ),
        )

    services = payload.get("services")
    if isinstance(services, list):
        evidence: list[ServiceEvidence] = []
        for item in services:
            if not isinstance(item, dict):
                continue
            if "port" not in item:
                continue
            evidence.append(
                ServiceEvidence(
                    port=int(item.get("port", 0)),
                    protocol=str(item.get("protocol", "tcp")),
                    state=str(item.get("state")) if item.get("state") is not None else None,
                    service=str(item.get("service") or item.get("service_name"))
                    if item.get("service") or item.get("service_name")
                    else None,
                )
            )
        return tuple(evidence)
    return ()


def _to_device_observations(assets: list[dict[str, Any]]) -> list[DeviceObservation]:
    observed_at = datetime.now(timezone.utc)
    observations: list[DeviceObservation] = []

    for asset in assets:
        source_observations = asset.get("source_observations")
        if isinstance(source_observations, dict) and source_observations:
            for collector, payload in source_observations.items():
                if not isinstance(payload, dict):
                    continue
                observations.append(
                    DeviceObservation(
                        provenance=SourceProvenance(
                            collector=str(collector),
                            artifact_path="discovery/latest.json",
                            run_id="reconcile",
                            observed_at=observed_at,
                        ),
                        ip=str(payload.get("ip") or payload.get("ip_address") or asset.get("ip_address") or "") or None,
                        mac=str(payload.get("mac") or payload.get("mac_address") or asset.get("mac_address") or "") or None,
                        hostname=str(payload.get("hostname") or asset.get("hostname") or "") or None,
                        services=_service_evidence_from_payload(payload),
                        first_seen_at=observed_at,
                        last_seen_at=observed_at,
                    )
                )
        else:
            observations.append(
                DeviceObservation(
                    provenance=SourceProvenance(
                        collector="reconcile_input",
                        artifact_path="discovery/latest.json",
                        run_id="reconcile",
                        observed_at=observed_at,
                    ),
                    ip=str(asset.get("ip_address") or "") or None,
                    mac=str(asset.get("mac_address") or "") or None,
                    hostname=str(asset.get("hostname") or "") or None,
                    services=(),
                    first_seen_at=observed_at,
                    last_seen_at=observed_at,
                )
            )

    return observations


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

    reconciliation = reconcile_observations(_to_device_observations(assets))

    for identity in reconciliation.identities:
        now = _now_iso()
        asset_uid = identity.identity_key
        asset_payload = {
            "asset_uid": asset_uid,
            "mac_address": identity.macs[0] if identity.macs else None,
            "ip_address": identity.ips[0] if identity.ips else None,
            "hostname": identity.hostnames[0] if identity.hostnames else None,
            "first_seen_at": now,
            "last_seen_at": now,
            "source_collector": "reconcile",
            "raw_artifact_path": None,
            "raw_artifact_hash": None,
            "confidence": 1.0,
            "status": "unknown" if not identity.macs and not identity.hostnames else "active",
            "is_active": 1,
        }
        asset_id = storage.upsert_asset(asset_payload)

        identity_type, _, identity_value = identity.identity_key.partition(":")
        storage.upsert_identity(
            {
                "identity_uid": identity.identity_key,
                "asset_id": asset_id,
                "identity_type": identity_type or "unknown",
                "identity_value": identity_value or identity.identity_key,
                "first_seen_at": now,
                "last_seen_at": now,
                "source_collector": "reconcile",
                "raw_artifact_path": None,
                "raw_artifact_hash": None,
                "confidence": 1.0,
                "status": "active",
                "is_verified": 0,
            }
        )

        source_observations: dict[str, dict[str, Any]] = {}
        for observation in identity.observations:
            source_observations[observation.provenance.collector] = {
                "ip_address": observation.ip,
                "mac_address": observation.mac,
                "hostname": observation.hostname,
            }

        snapshot = {
            "asset_uid": asset_uid,
            "mac_address": identity.macs[0] if identity.macs else None,
            "ip_address": identity.ips[0] if identity.ips else None,
            "hostname": identity.hostnames[0] if identity.hostnames else None,
            "status": "unknown" if not identity.macs and not identity.hostnames else "active",
            "sources": sorted({obs.provenance.collector for obs in identity.observations}),
            "source_observations": source_observations,
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
            "observation_key": asset_uid,
            "observation_value": snapshot_json,
            "source_collector": "reconcile",
            "raw_artifact_path": None,
            "raw_artifact_hash": sha256(snapshot_json.encode("utf-8")).hexdigest(),
            "confidence": 1.0,
            "status": "observed",
            "is_deleted": 0,
        }
        storage.upsert_observation(observation_payload)

    for contradiction in reconciliation.discrepancies:
        storage.upsert_discrepancy(
            {
                "run_id": run_id,
                "asset_id": None,
                "service_id": None,
                "baseline_id": None,
                "discrepancy_type": "reconcile_contradiction",
                "fingerprint": contradiction.category,
                "details": contradiction.detail,
                "detected_at": _now_iso(),
                "resolved_at": None,
                "source_collector": "reconcile",
                "raw_artifact_path": None,
                "raw_artifact_hash": None,
                "confidence": 1.0,
                "status": "open",
                "is_acknowledged": 0,
            }
        )

    storage.connection.commit()
    return ReconcileResult(run_id=run_id, run_uuid=resolved_run_uuid, asset_count=len(reconciliation.identities))
