"""CLI pipeline sequencing contracts."""

from __future__ import annotations

import argparse

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
