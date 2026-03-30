"""CLI plan command contracts."""

from __future__ import annotations

import argparse
import json

from homeadmin import cli


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
