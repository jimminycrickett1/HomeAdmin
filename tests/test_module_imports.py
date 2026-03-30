"""Importability contracts for critical HomeAdmin modules."""

from __future__ import annotations

import importlib


def test_critical_modules_import_cleanly() -> None:
    for module_name in (
        "homeadmin.cli",
        "homeadmin.config",
        "homeadmin.reconcile",
        "homeadmin.reconcile.merge",
        "homeadmin.reconcile.workflow",
        "homeadmin.drift",
        "homeadmin.drift.classifier",
        "homeadmin.drift.workflow",
        "homeadmin.execute",
        "homeadmin.execute.workflow",
        "homeadmin.plans",
        "homeadmin.plans.workflow",
        "homeadmin.agent",
        "homeadmin.agent.workflow",
    ):
        module = importlib.import_module(module_name)
        assert module is not None
