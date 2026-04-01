"""Storage initialization and upsert behavior contracts."""

from __future__ import annotations

import sqlite3

from homeadmin.storage import Storage


def test_storage_uses_sqlite_backend(tmp_path) -> None:
    storage = Storage(tmp_path / "state.db")
    conn = storage.connection

    assert isinstance(conn, sqlite3.Connection)


def test_storage_initialize_creates_schema(tmp_path) -> None:
    storage = Storage(tmp_path / "state.db")
    storage.initialize()

    row = storage.connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='runs'"
    ).fetchone()
    assert row is not None


def test_storage_upsert_run_is_idempotent_by_run_uuid(tmp_path) -> None:
    storage = Storage(tmp_path / "state.db")
    storage.initialize()

    payload = {
        "run_uuid": "run-1",
        "source_collector": "test",
        "started_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:01:00+00:00",
        "raw_artifact_path": None,
        "raw_artifact_hash": None,
        "confidence": 1.0,
        "status": "completed",
        "is_partial": 0,
    }

    first_id = storage.upsert_run(payload)
    second_id = storage.upsert_run(payload)

    assert first_id == second_id


def test_storage_upsert_recommendation_insert_update_and_read(tmp_path) -> None:
    storage = Storage(tmp_path / "state.db")
    storage.initialize()

    recommendation = {
        "id": "rec-001",
        "category": "network_exposure",
        "title": "Baseline exposed service",
        "rationale": "Service is exposed without a baseline approval entry.",
        "impact_score": 0.9,
        "risk_score": 0.7,
        "effort_score": 0.2,
        "confidence": 0.95,
        "priority_rank": 5,
    }

    first_id = storage.upsert_recommendation(recommendation)
    row = storage.get_recommendation("rec-001")

    assert row is not None
    assert first_id == int(row["id"])
    assert row["title"] == "Baseline exposed service"
    assert float(row["risk_score"]) == 0.7

    updated = {**recommendation, "title": "Baseline exposed service (updated)", "risk_score": 0.85}
    second_id = storage.upsert_recommendation(updated)
    updated_row = storage.get_recommendation("rec-001")

    assert updated_row is not None
    assert first_id == second_id
    assert updated_row["title"] == "Baseline exposed service (updated)"
    assert float(updated_row["risk_score"]) == 0.85


def test_storage_upsert_recommendation_evidence_link_is_idempotent(tmp_path) -> None:
    storage = Storage(tmp_path / "state.db")
    storage.initialize()

    run_id = storage.upsert_run(
        {
            "run_uuid": "run-rec-evidence",
            "source_collector": "test",
            "started_at": "2026-01-01T00:00:00+00:00",
            "finished_at": "2026-01-01T00:01:00+00:00",
            "raw_artifact_path": None,
            "raw_artifact_hash": None,
            "confidence": 1.0,
            "status": "completed",
            "is_partial": 0,
        }
    )
    asset_id = storage.upsert_asset(
        {
            "asset_uid": "asset-rec-001",
            "mac_address": "00:11:22:33:44:55",
            "ip_address": "192.168.1.10",
            "hostname": "lab-node",
            "first_seen_at": "2026-01-01T00:00:00+00:00",
            "last_seen_at": "2026-01-01T00:01:00+00:00",
            "source_collector": "test",
            "raw_artifact_path": None,
            "raw_artifact_hash": None,
            "confidence": 1.0,
            "status": "active",
            "is_active": 1,
        }
    )
    discrepancy_id = storage.upsert_discrepancy(
        {
            "run_id": run_id,
            "asset_id": asset_id,
            "service_id": None,
            "baseline_id": None,
            "discrepancy_type": "unexpected_service",
            "fingerprint": "tcp/22:ssh",
            "details": "Observed but not expected",
            "detected_at": "2026-01-01T00:01:00+00:00",
            "resolved_at": None,
            "source_collector": "test",
            "raw_artifact_path": None,
            "raw_artifact_hash": None,
            "confidence": 1.0,
            "status": "open",
            "is_acknowledged": 0,
        }
    )
    recommendation_id = storage.upsert_recommendation(
        {
            "id": "rec-002",
            "category": "drift",
            "title": "Investigate discrepancy",
            "rationale": "Discrepancy persists across runs.",
            "impact_score": 0.8,
            "risk_score": 0.6,
            "effort_score": 0.3,
            "confidence": 0.9,
            "priority_rank": 7,
        }
    )

    payload = {
        "recommendation_id": recommendation_id,
        "run_id": run_id,
        "discrepancy_id": discrepancy_id,
        "asset_id": asset_id,
    }
    first_link_id = storage.upsert_recommendation_evidence_link(payload)
    second_link_id = storage.upsert_recommendation_evidence_link(payload)
    links = storage.list_recommendation_evidence_links(recommendation_id)

    assert first_link_id == second_link_id
    assert len(links) == 1
    assert int(links[0]["run_id"]) == run_id
    assert int(links[0]["discrepancy_id"]) == discrepancy_id
    assert int(links[0]["asset_id"]) == asset_id
