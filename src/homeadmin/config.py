"""Configuration models and loading helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class AppConfig:
    """Application-level configuration."""

    state_dir: Path = Path(".homeadmin")


def load_config() -> AppConfig:
    """Load the HomeAdmin configuration.

    Returns:
        A validated :class:`AppConfig` instance.
    """
    return AppConfig()
