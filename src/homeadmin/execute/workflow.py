"""Plan execution workflow with strict policy enforcement."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_network
import hashlib
import json
import subprocess
from typing import Any, Mapping

from homeadmin.config import AppConfig
from homeadmin.storage.db import Storage


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """Outcome for one plan execution request."""

    execution_run_id: int | None
    status: str
    dry_run: bool
    policy_passed: tuple[str, ...]
    policy_failed: tuple[str, ...]
    step_count: int
    reused_existing: bool


def execute_plan(*, storage: Storage, config: AppConfig, plan_id: int, dry_run: bool, actor: str) -> ExecutionResult:
    """Execute a previously approved plan under strict policy controls."""
    plan = storage.get_plan(plan_id)
    if plan is None:
        return ExecutionResult(None, "not_found", dry_run, tuple(), ("plan_not_found",), 0, False)

    plan_hash = str(plan["plan_hash"])
    state = storage.get_plan_state(plan_id)
    policy_passed: list[str] = []
    policy_failed: list[str] = []

    if state == "approved":
        policy_passed.append("approved_state_verified")
    else:
        policy_failed.append(f"plan_not_approved:{state}")

    if dry_run:
        policy_passed.append("dry_run_enabled")
    elif config.execute_apply_enabled:
        policy_passed.append("apply_explicitly_enabled")
    else:
        policy_failed.append("apply_disabled_by_policy")

    if not _is_within_maintenance_window(config.execute_maintenance_windows):
        policy_failed.append("outside_maintenance_window")
    else:
        policy_passed.append("maintenance_window_open")

    active_changes = storage.count_running_apply_executions()
    if not dry_run and active_changes >= config.execute_max_concurrent_changes:
        policy_failed.append("max_concurrent_changes_exceeded")
    else:
        policy_passed.append("concurrency_within_limit")

    steps = _execution_steps_from_plan(plan)
    if not steps:
        policy_failed.append("missing_execution_steps")

    for step in steps:
        action_type = str(step.get("action_type", "")).strip()
        if action_type not in config.execute_allowed_action_types:
            policy_failed.append(f"action_type_not_allowlisted:{action_type}")
        target_scope = str(step.get("target_scope", "")).strip()
        if not _target_scope_allowed(target_scope, config.execute_allowed_target_scopes):
            policy_failed.append(f"target_scope_not_allowlisted:{target_scope}")
        if not str(step.get("command", "")).strip():
            policy_failed.append("missing_step_command")

    if policy_failed:
        return ExecutionResult(None, "blocked", dry_run, tuple(policy_passed), tuple(policy_failed), 0, False)

    existing = storage.get_execution_run(plan_id=plan_id, plan_hash=plan_hash, dry_run=dry_run)
    if existing and str(existing["status"]) == "succeeded":
        policy_passed.append("idempotent_reuse")
        return ExecutionResult(
            execution_run_id=int(existing["id"]),
            status="succeeded",
            dry_run=dry_run,
            policy_passed=tuple(policy_passed),
            policy_failed=tuple(policy_failed),
            step_count=storage.count_execution_steps(int(existing["id"])),
            reused_existing=True,
        )

    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with storage.transaction():
        run_id = storage.insert_execution_run(
            {
                "plan_id": plan_id,
                "plan_hash": plan_hash,
                "dry_run": 1 if dry_run else 0,
                "actor": actor,
                "status": "running",
                "policy_checks_json": json.dumps({"passed": policy_passed, "failed": policy_failed}, sort_keys=True),
                "started_at": started_at,
                "finished_at": None,
            }
        )

    final_status = "succeeded"
    for idx, step in enumerate(steps, start=1):
        result = _run_step(step=step, dry_run=dry_run)
        with storage.transaction():
            storage.insert_execution_step_result(
                {
                    "execution_run_id": run_id,
                    "step_order": idx,
                    "step_id": str(step.get("id", f"step-{idx}")),
                    "action_type": str(step.get("action_type", "")),
                    "target_scope": str(step.get("target_scope", "")),
                    "command": result["command"],
                    "args_json": json.dumps(result["args"], sort_keys=True),
                    "environment_policy_json": json.dumps(result["environment_policy"], sort_keys=True),
                    "stdout": result["stdout"],
                    "stderr": result["stderr"],
                    "exit_code": result["exit_code"],
                    "artifact_hash": result["artifact_hash"],
                }
            )
        if int(result["exit_code"]) != 0:
            final_status = "failed"
            break

    finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with storage.transaction():
        storage.update_execution_run_status(run_id, status=final_status, finished_at=finished_at)
        if final_status == "succeeded" and not dry_run:
            storage.append_plan_state_event(
                plan_id=plan_id,
                event_type="executed",
                actor=actor,
                plan_hash=plan_hash,
                policy_checks={"passed": policy_passed, "failed": policy_failed},
                metadata={"execution_run_id": run_id, "mode": "apply"},
            )

    return ExecutionResult(run_id, final_status, dry_run, tuple(policy_passed), tuple(policy_failed), len(steps), False)


def _execution_steps_from_plan(plan: Mapping[str, object]) -> list[dict[str, object]]:
    provenance = plan.get("provenance")
    if not isinstance(provenance, Mapping):
        return []
    execution_spec = provenance.get("execution")
    if not isinstance(execution_spec, Mapping):
        return []
    raw_steps = execution_spec.get("steps")
    if not isinstance(raw_steps, list):
        return []
    steps: list[dict[str, object]] = []
    for item in raw_steps:
        if isinstance(item, Mapping):
            steps.append(dict(item))
    return steps


def _is_within_maintenance_window(windows: tuple[str, ...]) -> bool:
    if not windows:
        return False
    now = datetime.now(timezone.utc)
    weekday = now.strftime("%a").lower()
    minute = now.hour * 60 + now.minute

    for window in windows:
        raw = window.strip()
        if raw == "*":
            return True
        has_day = "@" in raw
        if has_day:
            day_part, _, time_part = raw.partition("@")
            allowed_days = {part.strip().lower() for part in day_part.split(",") if part.strip()}
        else:
            time_part = raw
            allowed_days = {weekday}
        if weekday not in allowed_days:
            continue
        start_s, _, end_s = time_part.partition("-")
        if not end_s:
            continue
        start_m = _to_minutes(start_s)
        end_m = _to_minutes(end_s)
        if start_m <= minute <= end_m:
            return True
    return False


def _to_minutes(value: str) -> int:
    hour_s, _, minute_s = value.strip().partition(":")
    return int(hour_s) * 60 + int(minute_s)


def _target_scope_allowed(target_scope: str, allowlisted: tuple[str, ...]) -> bool:
    if target_scope in allowlisted:
        return True
    if target_scope.startswith("asset:"):
        return target_scope in allowlisted

    try:
        target_net = ip_network(target_scope, strict=False)
    except ValueError:
        return False

    for item in allowlisted:
        try:
            candidate = ip_network(item, strict=False)
        except ValueError:
            continue
        if target_net.subnet_of(candidate):
            return True
    return False


def _run_step(*, step: Mapping[str, object], dry_run: bool) -> dict[str, Any]:
    command = str(step.get("command", "")).strip()
    args = [str(item) for item in step.get("args", [])] if isinstance(step.get("args"), list) else []
    env_policy = {"mode": "inherit_none", "allowlisted_keys": []}

    if dry_run:
        stdout = f"DRY-RUN: {command} {' '.join(args)}".strip()
        stderr = ""
        exit_code = 0
    else:
        try:
            completed = subprocess.run(
                [command, *args],
                capture_output=True,
                text=True,
                check=False,
                env={},
            )
            stdout = completed.stdout
            stderr = completed.stderr
            exit_code = int(completed.returncode)
        except FileNotFoundError as exc:
            stdout = ""
            stderr = str(exc)
            exit_code = 127

    digest = hashlib.sha256((stdout + "\n" + stderr + "\n" + str(exit_code)).encode("utf-8")).hexdigest()
    return {
        "command": command,
        "args": args,
        "environment_policy": env_policy,
        "stdout": stdout,
        "stderr": stderr,
        "exit_code": exit_code,
        "artifact_hash": digest,
    }
