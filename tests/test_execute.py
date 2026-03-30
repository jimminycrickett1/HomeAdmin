"""Execution subsystem policy and idempotency tests."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from homeadmin.config import AppConfig
from homeadmin.execute import execute_plan
from homeadmin.plans import plan_content_hash
from homeadmin.storage.db import Storage


def _config(tmp_path: Path, *, apply_enabled: bool = False, max_concurrent: int = 1) -> AppConfig:
    return AppConfig(
        state_dir=tmp_path,
        allowed_cidrs=("192.168.1.0/24",),
        arp_scan_interface="eth0",
        nmap_interface="eth0",
        arp_scan_max_seconds=120,
        nmap_max_rate=100,
        execute_allowed_action_types=("noop",),
        execute_allowed_target_scopes=("asset:asset-1", "192.168.1.0/24"),
        execute_maintenance_windows=("*",),
        execute_max_concurrent_changes=max_concurrent,
        execute_apply_enabled=apply_enabled,
    )


def _persist_approved_plan(storage: Storage) -> int:
    plan = {
        "plan_key": "rule:asset-1",
        "title": "safe noop",
        "recommendation_rule_id": "rule",
        "asset_uid": "asset-1",
        "priority": "low",
        "prerequisites": [],
        "ordered_steps": ["run noop"],
        "expected_outcomes": [],
        "rollback_steps": [],
        "verification_checks": [],
        "blast_radius_estimate": "single-asset",
        "required_privilege_level": "operator",
        "provenance": {
            "execution": {
                "steps": [
                    {
                        "id": "noop-1",
                        "action_type": "noop",
                        "target_scope": "asset:asset-1",
                        "command": "echo",
                        "args": ["ok"],
                    }
                ]
            }
        },
    }
    digest = plan_content_hash(plan)
    with storage.transaction():
        plan_id, _, _ = storage.persist_compiled_plan(
            plan,
            source_run_id=0,
            generated_at="2026-01-01T00:00:00+00:00",
            plan_hash=digest,
            created_by="test",
        )
        storage.append_plan_state_event(
            plan_id=plan_id,
            event_type="approved",
            actor="tester",
            plan_hash=digest,
            policy_checks={"passed": ["ok"], "failed": []},
            metadata={},
        )
    return plan_id


def test_execute_policy_denies_non_allowlisted_action(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "state.db")
    storage.initialize()
    plan_id = _persist_approved_plan(storage)

    blocked_cfg = _config(tmp_path)
    result = execute_plan(storage=storage, config=blocked_cfg, plan_id=plan_id, dry_run=True, actor="ops")

    assert result.status == "succeeded"

    disallow_cfg = replace(blocked_cfg, execute_allowed_action_types=("different",))
    blocked = execute_plan(storage=storage, config=disallow_cfg, plan_id=plan_id, dry_run=True, actor="ops")
    assert blocked.status == "blocked"
    assert any(item.startswith("action_type_not_allowlisted") for item in blocked.policy_failed)


def test_execute_requires_apply_enablement_and_supports_dry_run(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "state.db")
    storage.initialize()
    plan_id = _persist_approved_plan(storage)

    dry_result = execute_plan(storage=storage, config=_config(tmp_path, apply_enabled=False), plan_id=plan_id, dry_run=True, actor="ops")
    assert dry_result.status == "succeeded"
    row = storage.connection.execute("SELECT dry_run, status FROM execution_runs WHERE id = ?", (dry_result.execution_run_id,)).fetchone()
    assert row is not None
    assert int(row["dry_run"]) == 1
    assert str(row["status"]) == "succeeded"

    apply_result = execute_plan(storage=storage, config=_config(tmp_path, apply_enabled=False), plan_id=plan_id, dry_run=False, actor="ops")
    assert apply_result.status == "blocked"
    assert "apply_disabled_by_policy" in apply_result.policy_failed


def test_execute_idempotent_rerun_reuses_existing_result(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "state.db")
    storage.initialize()
    plan_id = _persist_approved_plan(storage)
    cfg = _config(tmp_path, apply_enabled=True)

    first = execute_plan(storage=storage, config=cfg, plan_id=plan_id, dry_run=True, actor="ops")
    second = execute_plan(storage=storage, config=cfg, plan_id=plan_id, dry_run=True, actor="ops")

    assert first.status == "succeeded"
    assert second.status == "succeeded"
    assert second.reused_existing is True
    assert second.execution_run_id == first.execution_run_id
    count = storage.connection.execute("SELECT COUNT(*) AS count FROM execution_runs").fetchone()["count"]
    assert int(count) == 1
