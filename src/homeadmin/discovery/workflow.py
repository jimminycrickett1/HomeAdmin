"""Discovery workflow orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from homeadmin.collectors import collect_arp_scan, collect_nmap
from homeadmin.collectors.arp_scan import CollectorRecord as ArpScanRecord
from homeadmin.collectors.arp_scan import parse_arp_scan_output
from homeadmin.collectors.nmap import CollectorRecord as NmapRecord
from homeadmin.collectors.nmap import parse_nmap_gnmap_output
from homeadmin.config import AppConfig
from homeadmin.normalizers import normalize_observation
from homeadmin.storage.db import Storage


@dataclass(frozen=True, slots=True)
class DiscoverResult:
    """Result of a discover run."""

    run_id: int
    run_uuid: str
    collection_jobs: int
    observation_count: int
    asset_count: int
    discovery_path: Path
    is_partial: bool
    failed_collectors: tuple[str, ...]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _collector_config(config: AppConfig, collector: str) -> dict[str, Any]:
    interface = config.arp_scan_interface if collector == "arp_scan" else config.nmap_interface
    payload: dict[str, Any] = {
        "interface": interface,
        "allowed_cidrs": list(config.allowed_cidrs),
        "scan_cidrs": list(config.allowed_cidrs),
    }
    if collector == "arp_scan":
        payload["extra_args"] = [f"--timeout={config.arp_scan_max_seconds}"]
    else:
        payload["extra_args"] = ["-oG", "-", f"--max-rate={config.nmap_max_rate}"]
    return payload


def _persist_collection_job(storage: Storage, *, run_id: int, record: ArpScanRecord | NmapRecord) -> tuple[int, Path, str]:
    command_artifact = next(item for item in record.artifacts if item.label == "command.v1.json")
    stdout_artifact = next(item for item in record.artifacts if item.label == "stdout.v1.txt")
    job_id = storage.upsert_collection_job(
        {
            "run_id": run_id,
            "job_key": f"{record.collector_name}:{record.run_id}",
            "source_collector": record.collector_name,
            "started_at": record.started_at.isoformat(),
            "finished_at": record.finished_at.isoformat(),
            "raw_artifact_path": str(command_artifact.path),
            "raw_artifact_hash": command_artifact.sha256_hex,
            "confidence": 1.0,
            "status": "completed" if record.return_code == 0 else "failed",
            "is_retry": 0,
        }
    )
    return job_id, stdout_artifact.path, stdout_artifact.sha256_hex


def _persist_failed_collection_job(storage: Storage, *, run_id: int, collector_name: str, run_uuid: str) -> None:
    now_iso = _now_iso()
    storage.upsert_collection_job(
        {
            "run_id": run_id,
            "job_key": f"{collector_name}:{run_uuid}",
            "source_collector": collector_name,
            "started_at": now_iso,
            "finished_at": now_iso,
            "raw_artifact_path": None,
            "raw_artifact_hash": None,
            "confidence": 0.0,
            "status": "failed",
            "is_retry": 0,
        }
    )


def run_discovery(config: AppConfig, storage: Storage, *, state_dir: Path) -> DiscoverResult:
    """Run enabled collectors and persist provenance-aware discovery outputs."""

    run_uuid = str(uuid4())
    started_at = _now_iso()
    run_id = storage.upsert_run(
        {
            "run_uuid": run_uuid,
            "source_collector": "discover",
            "started_at": started_at,
            "finished_at": started_at,
            "raw_artifact_path": str(state_dir / "artifacts" / run_uuid),
            "raw_artifact_hash": None,
            "confidence": 1.0,
            "status": "running",
            "is_partial": 0,
        }
    )

    collectors: list[tuple[str, list[dict[str, Any]], int, Path, str]] = []
    failed_collectors: list[str] = []

    collector_specs: list[
        tuple[
            str,
            Callable[[dict[str, Any]], ArpScanRecord | NmapRecord],
            Callable[[str], list[dict[str, Any]]],
        ]
    ] = [
        (
            "arp_scan",
            lambda payload: collect_arp_scan(payload, run_id=run_uuid, run_root=state_dir),
            lambda stdout: [dict(item) for item in parse_arp_scan_output(stdout)],
        ),
        (
            "nmap",
            lambda payload: collect_nmap(payload, run_id=run_uuid, run_root=state_dir),
            lambda stdout: [dict(item) for item in parse_nmap_gnmap_output(stdout)],
        ),
    ]

    for collector_name, collector_fn, parser_fn in collector_specs:
        try:
            record = collector_fn(_collector_config(config, collector_name))
        except Exception:
            failed_collectors.append(collector_name)
            _persist_failed_collection_job(
                storage,
                run_id=run_id,
                collector_name=collector_name,
                run_uuid=run_uuid,
            )
            continue

        job_id, stdout_path, stdout_hash = _persist_collection_job(storage, run_id=run_id, record=record)
        if record.return_code != 0:
            failed_collectors.append(collector_name)
            continue

        rows = parser_fn(stdout_path.read_text(encoding="utf-8", errors="replace"))
        collectors.append((collector_name, rows, job_id, stdout_path, stdout_hash))

    assets_by_uid: dict[str, dict[str, Any]] = {}
    ip_to_uid: dict[str, str] = {}
    observation_count = 0

    for collector_name, rows, job_id, raw_path, raw_hash in collectors:
        expanded_rows: list[dict[str, Any]] = []
        for row in rows:
            services = row.get("services")
            if isinstance(services, list) and services:
                for service in services:
                    expanded_rows.append({"ip": row.get("ip"), "service": service})
            else:
                expanded_rows.append(row)

        for index, row in enumerate(expanded_rows):
            normalized = normalize_observation(row)
            mac_value = str(normalized.get("mac") or "").strip() or None
            ip_value = str(normalized.get("ip") or "").strip() or None
            asset_id: int | None = None

            if mac_value:
                if mac_value in assets_by_uid:
                    asset_uid = mac_value
                elif ip_value and ip_value in ip_to_uid:
                    prior_uid = ip_to_uid[ip_value]
                    prior_asset = assets_by_uid.pop(prior_uid)
                    prior_asset["asset_uid"] = mac_value
                    assets_by_uid[mac_value] = prior_asset
                    asset_uid = mac_value
                else:
                    asset_uid = mac_value
            elif ip_value:
                asset_uid = ip_to_uid.get(ip_value, ip_value)
            else:
                asset_uid = None

            if asset_uid:
                asset = assets_by_uid.setdefault(
                    asset_uid,
                    {
                        "asset_uid": asset_uid,
                        "mac_address": normalized.get("mac"),
                        "ip_address": normalized.get("ip"),
                        "hostname": normalized.get("hostname"),
                        "status": "active",
                        "sources": [],
                        "source_observations": {},
                    },
                )
                if normalized.get("mac"):
                    asset["mac_address"] = normalized.get("mac")
                if normalized.get("ip"):
                    asset["ip_address"] = normalized.get("ip")
                    ip_to_uid[str(normalized.get("ip"))] = asset_uid
                if normalized.get("hostname"):
                    asset["hostname"] = normalized.get("hostname")
                sources = asset.setdefault("sources", [])
                if collector_name not in sources:
                    sources.append(collector_name)
                source_observations = asset.setdefault("source_observations", {})
                source_observations[collector_name] = normalized

                now_iso = _now_iso()
                asset_payload = {
                    "asset_uid": asset_uid,
                    "mac_address": asset.get("mac_address"),
                    "ip_address": asset.get("ip_address"),
                    "hostname": asset.get("hostname"),
                    "first_seen_at": now_iso,
                    "last_seen_at": now_iso,
                    "source_collector": collector_name,
                    "raw_artifact_path": str(raw_path),
                    "raw_artifact_hash": raw_hash,
                    "confidence": 1.0,
                    "status": "active",
                    "is_active": 1,
                }
                asset_id = storage.upsert_asset(asset_payload)

            key = str(normalized.get("mac") or normalized.get("ip") or f"{collector_name}:{index}")
            payload_json = json.dumps(normalized, sort_keys=True)
            storage.upsert_observation(
                {
                    "run_id": run_id,
                    "collection_job_id": job_id,
                    "asset_id": asset_id,
                    "identity_id": None,
                    "service_id": None,
                    "observed_at": _now_iso(),
                    "observation_type": "discovery_observation",
                    "observation_key": f"{collector_name}:{index}:{key}",
                    "observation_value": payload_json,
                    "source_collector": collector_name,
                    "raw_artifact_path": str(raw_path),
                    "raw_artifact_hash": raw_hash,
                    "confidence": 1.0,
                    "status": "observed",
                    "is_deleted": 0,
                }
            )
            observation_count += 1

            mac_value = str(normalized.get("mac") or "").strip() or None
            ip_value = str(normalized.get("ip") or "").strip() or None

            if mac_value:
                if mac_value in assets_by_uid:
                    asset_uid = mac_value
                elif ip_value and ip_value in ip_to_uid:
                    prior_uid = ip_to_uid[ip_value]
                    prior_asset = assets_by_uid.pop(prior_uid)
                    prior_asset["asset_uid"] = mac_value
                    assets_by_uid[mac_value] = prior_asset
                    asset_uid = mac_value
                else:
                    asset_uid = mac_value
            elif ip_value:
                asset_uid = ip_to_uid.get(ip_value, ip_value)
            else:
                continue

            asset = assets_by_uid.setdefault(
                asset_uid,
                {
                    "asset_uid": asset_uid,
                    "mac_address": normalized.get("mac"),
                    "ip_address": normalized.get("ip"),
                    "hostname": normalized.get("hostname"),
                    "status": "active",
                    "sources": [],
                    "source_observations": {},
                },
            )
            if normalized.get("mac"):
                asset["mac_address"] = normalized.get("mac")
            if normalized.get("ip"):
                asset["ip_address"] = normalized.get("ip")
                ip_to_uid[str(normalized.get("ip"))] = asset_uid
            if normalized.get("hostname"):
                asset["hostname"] = normalized.get("hostname")
            sources = asset.setdefault("sources", [])
            if collector_name not in sources:
                sources.append(collector_name)
            source_observations = asset.setdefault("source_observations", {})
            source_observations[collector_name] = normalized

    assets = [assets_by_uid[key] for key in sorted(assets_by_uid.keys())]
    discovery_path = state_dir / "discovery" / "latest.json"
    discovery_path.parent.mkdir(parents=True, exist_ok=True)
    discovery_path.write_text(json.dumps(assets, indent=2, sort_keys=True), encoding="utf-8")

    is_partial = bool(failed_collectors)
    finished_at = _now_iso()
    storage.upsert_run(
        {
            "run_uuid": run_uuid,
            "source_collector": "discover",
            "started_at": started_at,
            "finished_at": finished_at,
            "raw_artifact_path": str(state_dir / "artifacts" / run_uuid),
            "raw_artifact_hash": None,
            "confidence": 1.0,
            "status": "partial" if is_partial else "completed",
            "is_partial": 1 if is_partial else 0,
        }
    )

    storage.connection.commit()
    return DiscoverResult(
        run_id=run_id,
        run_uuid=run_uuid,
        collection_jobs=2,
        observation_count=observation_count,
        asset_count=len(assets),
        discovery_path=discovery_path,
        is_partial=is_partial,
        failed_collectors=tuple(sorted(failed_collectors)),
    )
