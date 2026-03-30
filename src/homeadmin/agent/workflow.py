"""Deterministic AI orchestration scaffolding for recommendation planning.

This module intentionally does not execute commands. It only produces
structured, reviewable proposal payloads that can flow into the existing
plan approval workflow.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

_VARIANT_ORDER = ("minimal-risk", "balanced", "coverage-first")
_METHOD_BY_RULE: dict[str, tuple[str, ...]] = {
    "repeated_identity_evidence_contradictions": (
        "identity-evidence-review",
        "collector-config-audit",
    ),
    "assets_missing_expected_services": (
        "service-intent-validation",
        "baseline-expectation-update",
        "incident-escalation",
    ),
    "exposed_services_without_baseline_expectations": (
        "service-approval-verification",
        "baseline-registration",
        "containment-change-request",
    ),
    "stale_unknown_assets": (
        "identity-correlation-review",
        "asset-ownership-triage",
        "backlog-expiration-tracking",
    ),
}


def orchestrate_plan_variants(recommendation_payload: Mapping[str, Any]) -> dict[str, Any]:
    """Build deterministic plan variants and policy envelope for human approval.

    The returned structure is intentionally read-only and designed for review.
    It embeds an `approval_workflow_payload` shape that can be consumed by
    `homeadmin plan generate`.
    """

    generated_at = str(
        recommendation_payload.get("generated_at")
        or datetime.now(timezone.utc).isoformat(timespec="seconds")
    )
    source_run_id = int(recommendation_payload.get("source_run_id", 0) or 0)

    ordered = _ordered_recommendations(recommendation_payload.get("recommendations"))
    evidence_catalog = _evidence_catalog(ordered)

    variants: list[dict[str, Any]] = []
    for variant_id in _VARIANT_ORDER:
        selected = _variant_selection(ordered, variant_id=variant_id)
        variants.append(
            {
                "variant_id": variant_id,
                "summary": _variant_summary(variant_id, len(selected), len(ordered)),
                "tradeoffs": _variant_tradeoffs(variant_id),
                "justification": _variant_justification(variant_id, selected),
                "mapped_execution_methods": _map_execution_methods(selected),
                "approval_workflow_payload": {
                    "generated_at": generated_at,
                    "source_run_id": source_run_id,
                    "recommendations": selected,
                },
            }
        )

    return {
        "format_version": "1.0",
        "generated_at": generated_at,
        "source_run_id": source_run_id,
        "policy_envelope": {
            "read_only_default": True,
            "direct_command_execution": "forbidden",
            "execution_privileges": "none",
            "structured_plan_required": True,
            "requires_human_approval_for_apply": True,
        },
        "state_summary": {
            "recommendation_count": len(ordered),
            "high_priority_count": sum(1 for item in ordered if str(item.get("priority", "")).lower() == "high"),
            "covered_asset_uids": sorted(
                {str(item.get("asset_uid", "")).strip() for item in ordered if str(item.get("asset_uid", "")).strip()}
            ),
        },
        "evidence_catalog": evidence_catalog,
        "plan_variants": variants,
    }


def evaluate_orchestration_output(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Evaluate orchestration output for policy, determinism, and traceability."""

    failures: list[str] = []
    warnings: list[str] = []

    envelope = payload.get("policy_envelope")
    if not isinstance(envelope, Mapping):
        failures.append("missing_policy_envelope")
    else:
        if envelope.get("read_only_default") is not True:
            failures.append("read_only_default_not_true")
        if str(envelope.get("direct_command_execution", "")).lower() != "forbidden":
            failures.append("direct_command_execution_not_forbidden")
        if str(envelope.get("execution_privileges", "")).lower() != "none":
            failures.append("execution_privileges_not_none")
        if envelope.get("structured_plan_required") is not True:
            failures.append("structured_plan_requirement_missing")
        if envelope.get("requires_human_approval_for_apply") is not True:
            failures.append("human_approval_requirement_missing")

    evidence_catalog = payload.get("evidence_catalog")
    catalog_ids: set[str] = set()
    if not isinstance(evidence_catalog, list):
        failures.append("missing_evidence_catalog")
    else:
        for item in evidence_catalog:
            if not isinstance(item, Mapping):
                continue
            evidence_id = str(item.get("evidence_id", "")).strip()
            if evidence_id:
                catalog_ids.add(evidence_id)

    variants = payload.get("plan_variants")
    if not isinstance(variants, list) or not variants:
        failures.append("missing_plan_variants")
    else:
        seen_ids: set[str] = set()
        for variant in variants:
            if not isinstance(variant, Mapping):
                failures.append("invalid_variant_payload")
                continue
            variant_id = str(variant.get("variant_id", "")).strip()
            if not variant_id:
                failures.append("variant_id_missing")
            elif variant_id in seen_ids:
                failures.append("duplicate_variant_id")
            seen_ids.add(variant_id)

            workflow_payload = variant.get("approval_workflow_payload")
            if not isinstance(workflow_payload, Mapping):
                failures.append(f"{variant_id}:missing_approval_workflow_payload")
                continue
            if not _is_deterministic_order(workflow_payload.get("recommendations")):
                failures.append(f"{variant_id}:non_deterministic_recommendation_order")

            trace_failures = _traceability_failures(
                workflow_payload.get("recommendations"),
                catalog_ids,
            )
            failures.extend(f"{variant_id}:{item}" for item in trace_failures)

    if payload.get("format_version") != "1.0":
        warnings.append("unknown_format_version")

    return {
        "passed": not failures,
        "failure_count": len(failures),
        "warning_count": len(warnings),
        "failures": failures,
        "warnings": warnings,
    }


def _ordered_recommendations(raw: object) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    items = [dict(item) for item in raw if isinstance(item, Mapping)]
    return sorted(
        items,
        key=lambda item: (
            _priority_rank(str(item.get("priority", "low"))),
            str(item.get("rule_id", "")),
            str(item.get("asset_uid", "")),
        ),
    )


def _priority_rank(priority: str) -> int:
    lowered = priority.lower()
    if lowered == "high":
        return 0
    if lowered == "medium":
        return 1
    return 2


def _variant_selection(ordered: list[dict[str, Any]], *, variant_id: str) -> list[dict[str, Any]]:
    if variant_id == "coverage-first":
        return ordered
    if variant_id == "minimal-risk":
        return [item for item in ordered if str(item.get("priority", "")).lower() == "high"]
    return [
        item
        for item in ordered
        if str(item.get("priority", "")).lower() in {"high", "medium"}
    ]


def _variant_summary(variant_id: str, selected: int, total: int) -> str:
    if variant_id == "minimal-risk":
        return f"Focus only on highest-risk items ({selected}/{total}) for lowest operational change surface."
    if variant_id == "coverage-first":
        return f"Address full backlog coverage ({selected}/{total}) with highest operator effort."
    return f"Balance risk and effort by including high+medium priorities ({selected}/{total})."


def _variant_tradeoffs(variant_id: str) -> list[str]:
    if variant_id == "minimal-risk":
        return [
            "Lowest immediate blast radius.",
            "Leaves medium/low findings queued for later review.",
        ]
    if variant_id == "coverage-first":
        return [
            "Highest short-term operator workload.",
            "Maximizes closure of known recommendation backlog.",
        ]
    return [
        "Moderate operator workload.",
        "May defer low-priority hygiene tasks.",
    ]


def _variant_justification(variant_id: str, selected: list[dict[str, Any]]) -> str:
    evidence_refs = sorted(
        {
            evidence_id
            for item in selected
            for evidence_id in _recommendation_evidence_ids(item)
        }
    )
    evidence_blob = ", ".join(evidence_refs) if evidence_refs else "none"
    return f"Variant {variant_id} selected using deterministic priority ordering; evidence IDs: {evidence_blob}."


def _map_execution_methods(recommendations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    mapped: list[dict[str, Any]] = []
    for item in recommendations:
        rule_id = str(item.get("rule_id", "")).strip()
        methods = _METHOD_BY_RULE.get(rule_id, ("manual-investigation",))
        mapped.append(
            {
                "rule_id": rule_id,
                "asset_uid": str(item.get("asset_uid", "")).strip(),
                "execution_methods": list(methods),
            }
        )
    return mapped


def _evidence_catalog(recommendations: list[dict[str, Any]]) -> list[dict[str, str]]:
    entries: dict[str, dict[str, str]] = {}
    for item in recommendations:
        rule_id = str(item.get("rule_id", "")).strip()
        asset_uid = str(item.get("asset_uid", "")).strip()
        for evidence_id in _recommendation_evidence_ids(item):
            entries[evidence_id] = {
                "evidence_id": evidence_id,
                "rule_id": rule_id,
                "asset_uid": asset_uid,
            }
    return [entries[key] for key in sorted(entries)]


def _recommendation_evidence_ids(item: Mapping[str, Any]) -> list[str]:
    provenance = item.get("provenance")
    if not isinstance(provenance, Mapping):
        return []
    raw = provenance.get("evidence_ids")
    if not isinstance(raw, list):
        return []
    cleaned = [str(value).strip() for value in raw if str(value).strip()]
    return sorted(dict.fromkeys(cleaned))


def _is_deterministic_order(raw: object) -> bool:
    ordered = _ordered_recommendations(raw)
    if not isinstance(raw, list):
        return False
    given = [dict(item) for item in raw if isinstance(item, Mapping)]
    return given == ordered


def _traceability_failures(raw_recommendations: object, catalog_ids: set[str]) -> list[str]:
    if not isinstance(raw_recommendations, list):
        return ["missing_recommendations"]

    failures: list[str] = []
    for item in raw_recommendations:
        if not isinstance(item, Mapping):
            failures.append("invalid_recommendation_item")
            continue
        evidence_ids = _recommendation_evidence_ids(item)
        if not evidence_ids:
            failures.append("recommendation_missing_evidence_ids")
            continue
        for evidence_id in evidence_ids:
            if evidence_id not in catalog_ids:
                failures.append(f"evidence_not_cataloged:{evidence_id}")
    return failures
