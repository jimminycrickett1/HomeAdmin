"""Execution subsystem for approved plans."""

from homeadmin.execute.workflow import ExecutionResult, execute_plan

__all__ = ["execute_plan", "ExecutionResult"]
