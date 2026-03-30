"""Plan compilation and persistence contracts."""

from __future__ import annotations

import sqlite3

from homeadmin.plans import compile_plans, plan_content_hash
from homeadmin.storage import Storage


def _recommendations_payload() -> dict[str, object]:
    return {
        "generated_at": "2026-03-30T00:00:00+00:00",
        "source_run_id": 42,
        "recommendations": [
            {
                "rule_id": "stale_unknown_assets",
                "title": "Triage stale unknown asset",
                "priority": "medium",
                "asset_uid": "asset-z",
                "provenance": {"discrepancy_ids": ["d1"]},
            },
            {
                "rule_id": "assets_missing_expected_services",
                "title": "Investigate missing asset services",
                "priority": "high",
                "asset_uid": "asset-a",
                "provenance": {"discrepancy_ids": ["d2"]},
            },
        ],
    }


def test_compile_plans_is_deterministic() -> None:
    payload = _recommendations_payload()

    first = compile_plans(payload)
    second = compile_plans(payload)

    assert first == second
    assert first["plan_count"] == 2
    first_plan = first["plans"][0]
    assert first_plan["recommendation_rule_id"] == "assets_missing_expected_services"
    assert first_plan["required_privilege_level"] == "admin"
    assert first_plan["rollback_steps"]


def test_plan_versions_are_immutable_and_incremented(tmp_path) -> None:
    storage = Storage(tmp_path / "state.db")
    storage.initialize()

    compiled = compile_plans(_recommendations_payload())
    plan = compiled["plans"][0]
    plan_hash = plan_content_hash(plan)

    with storage.transaction():
        plan_id, version, created = storage.persist_compiled_plan(
            plan,
            source_run_id=int(compiled["source_run_id"]),
            generated_at=str(compiled["generated_at"]),
            plan_hash=plan_hash,
            created_by="test",
        )
    assert created is True
    assert version == 1

    with storage.transaction():
        same_id, same_version, created = storage.persist_compiled_plan(
            plan,
            source_run_id=int(compiled["source_run_id"]),
            generated_at=str(compiled["generated_at"]),
            plan_hash=plan_hash,
            created_by="test",
        )
    assert created is False
    assert same_id == plan_id
    assert same_version == 1

    modified = dict(plan)
    modified["ordered_steps"] = [*modified["ordered_steps"], "Record post-change evidence hash."]

    with storage.transaction():
        plan_v2, version_v2, created = storage.persist_compiled_plan(
            modified,
            source_run_id=int(compiled["source_run_id"]),
            generated_at=str(compiled["generated_at"]),
            plan_hash=plan_content_hash(modified),
            created_by="test",
        )
    assert created is True
    assert version_v2 == 2
    assert plan_v2 != plan_id

    with storage.transaction():
        try:
            storage.connection.execute("UPDATE plans SET title = 'mutated' WHERE id = ?", (plan_id,))
        except sqlite3.IntegrityError:
            pass
        else:
            raise AssertionError("Expected immutable plan update to fail")
