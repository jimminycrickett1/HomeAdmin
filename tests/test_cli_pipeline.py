"""CLI pipeline sequencing contracts."""

from __future__ import annotations

import argparse
import json

from homeadmin import cli


def test_pipeline_runs_m3_sequence(monkeypatch) -> None:
    calls: list[str] = []

    def _stub(name: str):
        def _handler(_args: argparse.Namespace) -> int:
            calls.append(name)
            return 0

        return _handler

    monkeypatch.setattr(cli, "_cmd_discover", _stub("discover"))
    monkeypatch.setattr(cli, "_cmd_reconcile", _stub("reconcile"))
    monkeypatch.setattr(cli, "_cmd_baseline_create", _stub("baseline"))
    monkeypatch.setattr(cli, "_cmd_drift", _stub("drift"))
    monkeypatch.setattr(cli, "_cmd_report", _stub("report"))

    status = cli._cmd_pipeline(argparse.Namespace(state_dir=None, run_uuid=None))

    assert status == 0
    assert calls == ["discover", "reconcile", "baseline", "drift", "report"]


def test_cmd_recommend_consumes_drift_json(monkeypatch, tmp_path) -> None:
    drift_payload = {
        "generated_at": "2026-03-29T00:00:00+00:00",
        "latest_run_id": 7,
        "new": [],
        "missing": [],
        "source_contradictions": [],
        "unresolved_unknowns": [],
    }
    drift_path = tmp_path / "drift_report.json"
    drift_path.write_text(json.dumps(drift_payload), encoding="utf-8")

    monkeypatch.setattr(cli, "load_config", lambda: type("Cfg", (), {"state_dir": tmp_path})())

    status = cli._cmd_recommend(argparse.Namespace(state_dir=tmp_path, drift_json=drift_path))

    assert status == 0
    assert (tmp_path / "reports" / "recommendations.json").exists()
    assert (tmp_path / "reports" / "recommendations.md").exists()


def test_recommend_subcommand_contract_supports_state_dir() -> None:
    parser = cli.build_parser()

    args = parser.parse_args(["--state-dir", "/tmp/homeadmin-state", "recommend"])

    assert args.command == "recommend"
    assert args.state_dir is not None
    assert str(args.state_dir) == "/tmp/homeadmin-state"
    assert args.drift_json is None
    assert args.handler == cli._cmd_recommend


def test_report_does_not_call_discovery_or_reconcile(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(cli, "load_config", lambda: type("Cfg", (), {"state_dir": tmp_path})())

    def _forbidden(*_args, **_kwargs):
        raise AssertionError("discovery/reconcile should not be called during report generation")

    monkeypatch.setattr(cli, "run_discovery", _forbidden)
    monkeypatch.setattr(cli, "load_discovery_assets", _forbidden)
    monkeypatch.setattr(cli, "reconcile_assets", _forbidden)

    class _FakeStorage:
        def __init__(self, _db_path):
            self.initialized = False

        def initialize(self):
            self.initialized = True

    monkeypatch.setattr(cli, "Storage", _FakeStorage)
    monkeypatch.setattr(cli, "calculate_drift", lambda _storage: object())

    captured: dict[str, object] = {}

    class _Artifacts:
        json_path = tmp_path / "reports" / "drift_report.json"
        markdown_path = tmp_path / "reports" / "drift_report.md"
        recommendations_json_path = tmp_path / "reports" / "recommendations.json"
        recommendations_markdown_path = tmp_path / "reports" / "recommendations.md"

    def _fake_write_reports(result, output_dir):
        captured["result"] = result
        captured["output_dir"] = output_dir
        return _Artifacts()

    monkeypatch.setattr(cli, "write_reports", _fake_write_reports)

    status = cli._cmd_report(argparse.Namespace(state_dir=tmp_path))

    assert status == 0
    assert captured["output_dir"] == tmp_path / "reports"
