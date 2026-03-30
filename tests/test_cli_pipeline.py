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
    assert (tmp_path / "reports" / "recommendations_report.json").exists()
    assert (tmp_path / "reports" / "recommendations_report.md").exists()
