"""CLI discover behavior contracts."""

from __future__ import annotations

import argparse
from pathlib import Path

from homeadmin import cli
from homeadmin.discovery.workflow import DiscoverResult


class _FakeStorage:
    def __init__(self, _db_path: Path) -> None:
        pass

    def initialize(self) -> None:
        return None


def test_cmd_discover_returns_nonzero_for_partial_run(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cli, "Storage", _FakeStorage)
    monkeypatch.setattr(cli, "load_config", lambda: type("Cfg", (), {"state_dir": tmp_path})())
    monkeypatch.setattr(cli, "validate_discovery_scope", lambda _config: None)
    monkeypatch.setattr(
        cli,
        "run_discovery",
        lambda _config, _storage, *, state_dir: DiscoverResult(
            run_id=1,
            run_uuid="run-1",
            collection_jobs=2,
            observation_count=1,
            asset_count=1,
            discovery_path=state_dir / "discovery" / "latest.json",
            is_partial=True,
            failed_collectors=("nmap",),
        ),
    )

    status = cli._cmd_discover(argparse.Namespace(state_dir=tmp_path))

    assert status == 2
