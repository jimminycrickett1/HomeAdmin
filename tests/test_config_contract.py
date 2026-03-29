"""Configuration loading contract tests."""

from __future__ import annotations

from pathlib import Path

from homeadmin.config import AppConfig, load_config


def test_load_config_returns_app_config() -> None:
    config = load_config()
    assert isinstance(config, AppConfig)


def test_load_config_includes_state_dir_path() -> None:
    config = load_config()
    assert isinstance(config.state_dir, Path)
    assert str(config.state_dir)
