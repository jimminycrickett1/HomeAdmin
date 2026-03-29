"""CLI smoke tests."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys


def test_cli_help_module_smoke() -> None:
    root = Path(__file__).resolve().parents[1]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "src")

    completed = subprocess.run(
        [sys.executable, "-m", "homeadmin.cli", "--help"],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    assert "usage:" in completed.stdout.lower()


def test_cli_help_console_script_smoke_when_installed() -> None:
    executable = shutil.which("homeadmin")
    if executable is None:
        return

    completed = subprocess.run(
        [executable, "--help"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    assert "usage:" in completed.stdout.lower()
