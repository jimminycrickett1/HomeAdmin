"""Storage initialization and upsert behavior contracts."""

from __future__ import annotations

from homeadmin.storage import Storage


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
