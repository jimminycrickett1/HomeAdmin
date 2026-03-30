"""Contracts for AI orchestration plan outputs."""

from __future__ import annotations

import json
from pathlib import Path

from homeadmin.agent import evaluate_orchestration_output, orchestrate_plan_variants


def _fixture(name: str) -> dict[str, object]:
    path = Path(__file__).parent / "fixtures" / "agent" / name
    return json.loads(path.read_text(encoding="utf-8"))


def test_orchestration_output_is_policy_compliant_and_traceable() -> None:
    recommendations = _fixture("recommendations_input.json")

    output = orchestrate_plan_variants(recommendations)
    evaluation = evaluate_orchestration_output(output)

    assert output["policy_envelope"]["read_only_default"] is True
    assert output["policy_envelope"]["direct_command_execution"] == "forbidden"
    assert output["policy_envelope"]["requires_human_approval_for_apply"] is True
    assert evaluation["passed"] is True
    assert evaluation["failure_count"] == 0


def test_orchestration_output_is_deterministic_for_audit() -> None:
    recommendations = _fixture("recommendations_input.json")

    first = orchestrate_plan_variants(recommendations)
    second = orchestrate_plan_variants(recommendations)

    assert first == second
    assert [variant["variant_id"] for variant in first["plan_variants"]] == [
        "minimal-risk",
        "balanced",
        "coverage-first",
    ]


def test_evaluation_flags_non_compliant_fixture() -> None:
    invalid = _fixture("orchestration_invalid.json")

    evaluation = evaluate_orchestration_output(invalid)

    assert evaluation["passed"] is False
    assert "read_only_default_not_true" in evaluation["failures"]
    assert "direct_command_execution_not_forbidden" in evaluation["failures"]
    assert "execution_privileges_not_none" in evaluation["failures"]
    assert any(item.endswith("recommendation_missing_evidence_ids") for item in evaluation["failures"])
