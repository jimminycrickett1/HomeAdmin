"""CLI plan command contracts."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json

from homeadmin import cli
from homeadmin.plans import plan_content_hash
from homeadmin.storage import Storage


def test_cmd_plan_generate_from_recommendations_json(monkeypatch, tmp_path) -> None:
    recommendations = {
        "generated_at": "2026-03-30T00:00:00+00:00",
        "source_run_id": 3,
        "recommendations": [
            {
                "rule_id": "exposed_services_without_baseline_expectations",
                "title": "Review exposed services on newly observed asset",
                "priority": "medium",
                "asset_uid": "asset-1",
                "provenance": {},
            }
        ],
    }
    payload_path = tmp_path / "recommendations.json"
    payload_path.write_text(json.dumps(recommendations), encoding="utf-8")

    monkeypatch.setattr(cli, "load_config", lambda: type("Cfg", (), {"state_dir": tmp_path})())

    status = cli._cmd_plan_generate(
        argparse.Namespace(state_dir=tmp_path, recommendations_json=payload_path)
    )

    assert status == 0


def test_cli_plan_parser_commands_exist() -> None:
    parser = cli.build_parser()
    args = parser.parse_args(["plan", "show", "--id", "7"])

    assert args.command == "plan"
    assert args.id == 7
    execute_args = parser.parse_args(["execute", "--plan-id", "7", "--dry-run"])
    assert execute_args.command == "execute"
    assert execute_args.plan_id == 7


def test_plan_execution_requires_approval(monkeypatch, tmp_path) -> None:
    recommendations = {
        "generated_at": "2026-03-30T00:00:00+00:00",
        "source_run_id": 9,
        "recommendations": [
            {
                "rule_id": "stale_unknown_assets",
                "title": "Triage stale unknown asset",
                "priority": "medium",
                "asset_uid": "asset-7",
                "provenance": {},
            }
        ],
    }
    payload_path = tmp_path / "recommendations.json"
    payload_path.write_text(json.dumps(recommendations), encoding="utf-8")
    monkeypatch.setattr(cli, "load_config", lambda: type("Cfg", (), {"state_dir": tmp_path})())

    assert cli._cmd_plan_generate(argparse.Namespace(state_dir=tmp_path, recommendations_json=payload_path)) == 0

    storage = Storage(tmp_path / "homeadmin.db")
    storage.initialize()
    row = storage.connection.execute("SELECT id FROM plans ORDER BY id DESC LIMIT 1").fetchone()
    assert row is not None
    plan_id = int(row["id"])

    blocked = cli._cmd_plan_execute(argparse.Namespace(state_dir=tmp_path, id=plan_id, executed_by="ops", note=None))
    assert blocked == 2

    approved = cli._cmd_plan_approve(
        argparse.Namespace(
            state_dir=tmp_path,
            id=plan_id,
            approver="owner",
            reason="looks good",
            approval_token=None,
        )
    )
    assert approved == 0

    executed = cli._cmd_plan_execute(argparse.Namespace(state_dir=tmp_path, id=plan_id, executed_by="ops", note=None))
    assert executed == 0


def test_plan_approve_with_signed_token(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(cli, "load_config", lambda: type("Cfg", (), {"state_dir": tmp_path})())
    monkeypatch.setenv("HOMEADMIN_APPROVAL_TOKEN_SECRET", "secret-1")

    recommendations = {
        "generated_at": "2026-03-30T00:00:00+00:00",
        "source_run_id": 9,
        "recommendations": [
            {
                "rule_id": "stale_unknown_assets",
                "title": "Triage stale unknown asset",
                "priority": "medium",
                "asset_uid": "asset-9",
                "provenance": {},
            }
        ],
    }
    payload_path = tmp_path / "recommendations.json"
    payload_path.write_text(json.dumps(recommendations), encoding="utf-8")
    assert cli._cmd_plan_generate(argparse.Namespace(state_dir=tmp_path, recommendations_json=payload_path)) == 0

    storage = Storage(tmp_path / "homeadmin.db")
    storage.initialize()
    row = storage.connection.execute("SELECT id, plan_hash FROM plans ORDER BY id DESC LIMIT 1").fetchone()
    assert row is not None
    plan_id = int(row["id"])
    plan_hash = str(row["plan_hash"])

    payload = {"actor": "bot-owner", "plan_id": plan_id, "plan_hash": plan_hash}
    payload_raw = base64.urlsafe_b64encode(json.dumps(payload, sort_keys=True).encode("utf-8")).decode("utf-8")
    signature = hmac.new(b"secret-1", payload_raw.encode("utf-8"), hashlib.sha256).hexdigest()
    token = f"{payload_raw}.{signature}"

    status = cli._cmd_plan_approve(
        argparse.Namespace(
            state_dir=tmp_path,
            id=plan_id,
            approver=None,
            reason="ci approval",
            approval_token=token,
        )
    )
    assert status == 0


def test_cli_execute_command_dry_run(monkeypatch, tmp_path) -> None:
    storage = Storage(tmp_path / "homeadmin.db")
    storage.initialize()
    plan = {
        "plan_key": "exec:asset-1",
        "title": "Execute noop",
        "recommendation_rule_id": "rule",
        "asset_uid": "asset-1",
        "priority": "low",
        "prerequisites": [],
        "ordered_steps": [],
        "expected_outcomes": [],
        "rollback_steps": [],
        "verification_checks": [],
        "blast_radius_estimate": "single-asset",
        "required_privilege_level": "operator",
        "provenance": {
            "execution": {
                "steps": [
                    {
                        "id": "noop",
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
            generated_at="2026-03-30T00:00:00+00:00",
            plan_hash=digest,
            created_by="test",
        )
        storage.append_plan_state_event(
            plan_id=plan_id,
            event_type="approved",
            actor="owner",
            plan_hash=digest,
            policy_checks={"passed": ["ok"], "failed": []},
            metadata={},
        )

    cfg = type(
        "Cfg",
        (),
        {
            "state_dir": tmp_path,
            "execute_allowed_action_types": ("noop",),
            "execute_allowed_target_scopes": ("asset:asset-1",),
            "execute_maintenance_windows": ("*",),
            "execute_max_concurrent_changes": 1,
            "execute_apply_enabled": False,
        },
    )()
    monkeypatch.setattr(cli, "load_config", lambda: cfg)

    status = cli._cmd_execute(argparse.Namespace(state_dir=tmp_path, plan_id=plan_id, dry_run=True, apply=False))
    assert status == 0
