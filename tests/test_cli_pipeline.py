"""Pipeline command behavior contracts."""

from __future__ import annotations

import argparse

from homeadmin import cli


def test_pipeline_runs_in_m3_order(monkeypatch) -> None:
    calls: list[str] = []

    def _ok(name: str):
        def _handler(args: argparse.Namespace) -> int:
            calls.append(name)
            return 0

        return _handler

    monkeypatch.setattr(cli, "_cmd_discover", _ok("discover"))
    monkeypatch.setattr(cli, "_cmd_reconcile", _ok("reconcile"))
    monkeypatch.setattr(cli, "_cmd_baseline_create", _ok("baseline.create"))
    monkeypatch.setattr(cli, "_cmd_drift", _ok("drift"))
    monkeypatch.setattr(cli, "_cmd_report", _ok("report"))

    status = cli._cmd_pipeline(argparse.Namespace(state_dir=None, run_uuid=None))

    assert status == 0
    assert calls == ["discover", "reconcile", "baseline.create", "drift", "report"]


def test_pipeline_stops_on_first_failure(monkeypatch) -> None:
    calls: list[str] = []

    def discover(args: argparse.Namespace) -> int:
        calls.append("discover")
        return 0

    def reconcile(args: argparse.Namespace) -> int:
        calls.append("reconcile")
        return 2

    def baseline(args: argparse.Namespace) -> int:
        calls.append("baseline.create")
        return 0

    monkeypatch.setattr(cli, "_cmd_discover", discover)
    monkeypatch.setattr(cli, "_cmd_reconcile", reconcile)
    monkeypatch.setattr(cli, "_cmd_baseline_create", baseline)

    status = cli._cmd_pipeline(argparse.Namespace(state_dir=None, run_uuid=None))

    assert status == 2
    assert calls == ["discover", "reconcile"]
