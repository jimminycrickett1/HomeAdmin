"""Plan compilation and diffing for actionable recommendations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Mapping

_PRIORITY_ORDER = {"high": 0, "medium": 1, "low": 2}


@dataclass(frozen=True, slots=True)
class CompiledPlan:
    """Executable change plan generated from a recommendation."""

    plan_key: str
    title: str
    recommendation_rule_id: str
    asset_uid: str
    priority: str
    prerequisites: list[str]
    ordered_steps: list[str]
    expected_outcomes: list[str]
    rollback_steps: list[str]
    verification_checks: list[str]
    blast_radius_estimate: str
    required_privilege_level: str
    provenance: dict[str, Any]

    def to_record(self) -> dict[str, Any]:
        """Render an immutable dictionary representation of the plan."""
        return {
            "plan_key": self.plan_key,
            "title": self.title,
            "recommendation_rule_id": self.recommendation_rule_id,
            "asset_uid": self.asset_uid,
            "priority": self.priority,
            "prerequisites": list(self.prerequisites),
            "ordered_steps": list(self.ordered_steps),
            "expected_outcomes": list(self.expected_outcomes),
            "rollback_steps": list(self.rollback_steps),
            "verification_checks": list(self.verification_checks),
            "blast_radius_estimate": self.blast_radius_estimate,
            "required_privilege_level": self.required_privilege_level,
            "provenance": dict(self.provenance),
        }


def compile_plans(recommendation_payload: Mapping[str, Any]) -> dict[str, Any]:
    """Compile recommendations into deterministic, executable change plans."""
    generated_at = str(
        recommendation_payload.get("generated_at")
        or datetime.now(timezone.utc).isoformat(timespec="seconds")
    )
    source_run_id = int(recommendation_payload.get("source_run_id", 0) or 0)

    plans: list[CompiledPlan] = []
    raw_items = recommendation_payload.get("recommendations")
    if isinstance(raw_items, list):
        ordered = sorted(raw_items, key=_recommendation_sort_key)
        for item in ordered:
            if not isinstance(item, Mapping):
                continue
            plans.append(_compile_single_plan(item, source_run_id=source_run_id))

    return {
        "generated_at": generated_at,
        "source_run_id": source_run_id,
        "plan_count": len(plans),
        "plans": [plan.to_record() for plan in plans],
    }


def plan_content_hash(plan: Mapping[str, Any]) -> str:
    """Return a deterministic hash for plan versioning decisions."""
    canonical = json.dumps(plan, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_plan_diff(current: Mapping[str, Any], previous: Mapping[str, Any] | None) -> dict[str, Any]:
    """Build a structured diff against the prior plan version."""
    if previous is None:
        return {
            "has_previous": False,
            "changed_fields": sorted(current.keys()),
            "list_changes": {},
        }

    changed_fields = sorted(
        key for key in set(current) | set(previous) if current.get(key) != previous.get(key)
    )
    list_changes: dict[str, dict[str, list[str]]] = {}
    for key in (
        "prerequisites",
        "ordered_steps",
        "expected_outcomes",
        "rollback_steps",
        "verification_checks",
    ):
        current_values = [str(item) for item in current.get(key, []) if isinstance(item, str)]
        previous_values = [str(item) for item in previous.get(key, []) if isinstance(item, str)]
        added = [item for item in current_values if item not in previous_values]
        removed = [item for item in previous_values if item not in current_values]
        if added or removed:
            list_changes[key] = {"added": added, "removed": removed}

    return {
        "has_previous": True,
        "changed_fields": changed_fields,
        "list_changes": list_changes,
    }


def _recommendation_sort_key(item: Any) -> tuple[int, str, str]:
    if not isinstance(item, Mapping):
        return (99, "", "")
    priority = str(item.get("priority", "low")).lower()
    rule_id = str(item.get("rule_id", ""))
    asset_uid = str(item.get("asset_uid", ""))
    return (_PRIORITY_ORDER.get(priority, 3), rule_id, asset_uid)


def _compile_single_plan(item: Mapping[str, Any], *, source_run_id: int) -> CompiledPlan:
    rule_id = str(item.get("rule_id", "unknown_rule"))
    asset_uid = str(item.get("asset_uid", "unknown_asset"))
    title = str(item.get("title", "Recommendation"))
    priority = str(item.get("priority", "medium")).lower()

    plan_key = f"{rule_id}:{asset_uid}"

    template = _rule_template(rule_id=rule_id, asset_uid=asset_uid)
    provenance = {
        "source_run_id": source_run_id,
        "recommendation_rule_id": rule_id,
        "recommendation_provenance": item.get("provenance", {}),
    }

    return CompiledPlan(
        plan_key=plan_key,
        title=title,
        recommendation_rule_id=rule_id,
        asset_uid=asset_uid,
        priority=priority,
        prerequisites=template["prerequisites"],
        ordered_steps=template["ordered_steps"],
        expected_outcomes=template["expected_outcomes"],
        rollback_steps=template["rollback_steps"],
        verification_checks=template["verification_checks"],
        blast_radius_estimate=template["blast_radius_estimate"],
        required_privilege_level=template["required_privilege_level"],
        provenance=provenance,
    )


def _rule_template(rule_id: str, asset_uid: str) -> dict[str, Any]:
    generic = {
        "prerequisites": [
            f"Confirm maintenance window and operator ownership for asset {asset_uid}.",
            "Collect current configuration snapshot and checksum all artifacts.",
        ],
        "ordered_steps": [
            "Review recommendation provenance and validate evidence freshness.",
            "Apply the smallest reversible change needed to satisfy the recommendation.",
            "Record exact commands, operator identity, and timestamp in change log.",
        ],
        "expected_outcomes": [
            "Recommendation risk is reduced without expanding discovery scope.",
            "Post-change inventory remains reconcilable with source provenance.",
        ],
        "rollback_steps": [
            "Restore pre-change configuration snapshot.",
            "Re-run discovery and reconcile to confirm restoration.",
        ],
        "verification_checks": [
            "Run `homeadmin discover` and ensure no new collection errors.",
            "Run `homeadmin drift` and confirm targeted discrepancy decreases.",
        ],
        "blast_radius_estimate": "single-asset",
        "required_privilege_level": "operator",
    }

    if rule_id == "repeated_identity_evidence_contradictions":
        return {
            **generic,
            "ordered_steps": [
                "Inspect identity evidence records for contradictory values.",
                "Validate collector inputs and adjust identity mapping policy for the asset.",
                "Mark conflicting evidence as reviewed in operator notes.",
            ],
            "expected_outcomes": [
                "Contradictory identity evidence is explained or suppressed by policy.",
                "Future reconciliations produce consistent identity linkage.",
            ],
            "blast_radius_estimate": "multi-observation-single-asset",
            "required_privilege_level": "admin",
        }

    if rule_id == "assets_missing_expected_services":
        return {
            **generic,
            "ordered_steps": [
                "Confirm whether the missing service is intentionally retired or temporarily unavailable.",
                "If retirement is intended, update baseline expectation with justification.",
                "If outage is unintended, open incident and document remediation owner.",
            ],
            "expected_outcomes": [
                "Baseline expectations align with observed service state.",
                "Service outage status is documented for follow-up.",
            ],
            "blast_radius_estimate": "single-asset-service-set",
            "required_privilege_level": "admin",
        }

    if rule_id == "exposed_services_without_baseline_expectations":
        return {
            **generic,
            "ordered_steps": [
                "Validate each exposed service against approved inventory scope.",
                "For approved services, add baseline records with provenance.",
                "For unapproved services, initiate containment request through change process.",
            ],
            "expected_outcomes": [
                "All exposed services are either approved with baseline or queued for containment.",
                "Inventory reflects accurate expected exposure for the asset.",
            ],
            "blast_radius_estimate": "single-asset-network-exposure",
            "required_privilege_level": "admin",
        }

    if rule_id == "stale_unknown_assets":
        return {
            **generic,
            "ordered_steps": [
                "Correlate unknown fingerprint with known device registry and DHCP leases.",
                "Tag asset as identified, quarantined for review, or accepted unknown with expiration.",
                "Record decision and rationale in backlog tracking.",
            ],
            "expected_outcomes": [
                "Unknown asset backlog is reduced or intentionally deferred with expiry.",
                "Drift reporting reflects explicit operator decision state.",
            ],
            "blast_radius_estimate": "single-segment",
            "required_privilege_level": "operator",
        }

    return generic
