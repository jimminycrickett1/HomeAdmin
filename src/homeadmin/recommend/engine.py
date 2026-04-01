"""Recommendation generation engine for drift results."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from homeadmin.config import AppConfig, load_config
from homeadmin.drift import DriftResult


@dataclass(frozen=True, slots=True)
class RankedRecommendation:
    """Deterministic recommendation with weighted ranking metadata."""

    rule_id: str
    title: str
    asset_uid: str
    summary: str
    impact: float
    risk: float
    effort: float
    confidence: float
    score: float
    rank: int
    evidence_discrepancy_ids: tuple[int, ...]


def generate_ranked_recommendations(
    drift_result: DriftResult,
    discrepancy_records: Sequence[Mapping[str, Any]],
    *,
    config: AppConfig | None = None,
) -> list[dict[str, Any]]:
    """Generate conservative recommendations and return deterministic ranked output."""
    app_config = config or load_config()
    history = _build_discrepancy_history(discrepancy_records)

    candidates: list[dict[str, Any]] = []
    candidates.extend(_rule_unresolved_unknowns(drift_result, history))
    candidates.extend(_rule_source_contradictions(drift_result, history))
    candidates.extend(_rule_repeated_missing_expected(drift_result, history))
    candidates.extend(_rule_newly_exposed_services(drift_result, history))

    weighted = [_with_score(item, app_config) for item in candidates]
    ordered = sorted(
        weighted,
        key=lambda item: (
            -float(item["score"]),
            -float(item["risk"]),
            -float(item["impact"]),
            str(item["rule_id"]),
            str(item["asset_uid"]),
            str(item["summary"]),
        ),
    )
    for index, item in enumerate(ordered, start=1):
        item["rank"] = index
    return ordered


def _with_score(item: Mapping[str, Any], config: AppConfig) -> dict[str, Any]:
    impact = float(item["impact"])
    risk = float(item["risk"])
    effort = float(item["effort"])
    confidence = float(item["confidence"])
    score = (
        impact * config.recommend_impact_weight
        + risk * config.recommend_risk_weight
        + confidence * config.recommend_confidence_weight
        - effort * config.recommend_effort_weight
    )
    materialized = dict(item)
    materialized["score"] = round(score, 6)
    return materialized


def _build_discrepancy_history(records: Sequence[Mapping[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    history: dict[tuple[str, str], dict[str, Any]] = {}
    for row in records:
        discrepancy_type = str(row.get("discrepancy_type", "")).strip()
        fingerprint = str(row.get("fingerprint", "")).strip()
        if not discrepancy_type or not fingerprint:
            continue
        key = (discrepancy_type, fingerprint)
        existing = history.setdefault(key, {"count": 0, "ids": set()})
        existing["count"] = int(existing["count"]) + 1

        row_id = row.get("id")
        if isinstance(row_id, int):
            cast_ids = existing["ids"]
            if isinstance(cast_ids, set):
                cast_ids.add(row_id)

    normalized: dict[tuple[str, str], dict[str, Any]] = {}
    for key, value in history.items():
        ids = tuple(sorted(int(item) for item in value["ids"]))
        normalized[key] = {"count": int(value["count"]), "ids": ids}
    return normalized


def _rule_unresolved_unknowns(
    drift_result: DriftResult,
    history: Mapping[tuple[str, str], Mapping[str, Any]],
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for item in drift_result.unresolved_unknowns:
        fingerprint = str(item.get("unknown_fingerprint") or item.get("asset_uid") or "unknown")
        past = history.get(("unknown_backlog", fingerprint), {})
        recurrence = max(int(item.get("recurrence_count", 0) or 0), int(past.get("count", 0) or 0))
        output.append(
            {
                "rule_id": "unresolved_unknowns",
                "title": "Triage unresolved unknown asset",
                "asset_uid": str(item.get("asset_uid", "unknown")),
                "summary": (
                    f"Unknown asset fingerprint {fingerprint} is unresolved "
                    f"with recurrence={recurrence} and age_days={int(item.get('age_days', 0) or 0)}."
                ),
                "impact": 0.65,
                "risk": 0.8 if str(item.get("classification", "")) == "chronic_unknown" else 0.55,
                "effort": 0.45,
                "confidence": 0.9,
                "evidence_discrepancy_ids": tuple(int(v) for v in past.get("ids", ())),
            }
        )
    return output


def _rule_source_contradictions(
    drift_result: DriftResult,
    history: Mapping[tuple[str, str], Mapping[str, Any]],
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for item in drift_result.source_contradictions:
        asset_uid = str(item.get("asset_uid", "unknown"))
        past = history.get(("source_contradiction", asset_uid), {})
        recurrence = max(1, int(past.get("count", 0) or 0))
        if recurrence < 2:
            continue
        contradictions = tuple(sorted(str(x) for x in item.get("contradictions", [])))
        output.append(
            {
                "rule_id": "source_contradictions",
                "title": "Escalate repeated source contradictions",
                "asset_uid": asset_uid,
                "summary": f"Contradictions {contradictions} repeated {recurrence} times for identity evidence.",
                "impact": 0.7,
                "risk": 0.75,
                "effort": 0.35,
                "confidence": 0.88,
                "evidence_discrepancy_ids": tuple(int(v) for v in past.get("ids", ())),
            }
        )
    return output


def _rule_repeated_missing_expected(
    drift_result: DriftResult,
    history: Mapping[tuple[str, str], Mapping[str, Any]],
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for item in drift_result.missing:
        asset_uid = str(item.get("asset_uid", "unknown"))
        fingerprint = f"missing:{asset_uid}"
        past = history.get(("missing_expected_asset_or_service", fingerprint), {})
        recurrence = int(past.get("count", 0) or 0)
        if recurrence < 2:
            continue
        output.append(
            {
                "rule_id": "repeated_missing_expected_assets_services",
                "title": "Investigate repeatedly missing expected asset/services",
                "asset_uid": asset_uid,
                "summary": f"Expected asset/services absent repeatedly (recurrence={recurrence}).",
                "impact": 0.8,
                "risk": 0.72,
                "effort": 0.5,
                "confidence": 0.8,
                "evidence_discrepancy_ids": tuple(int(v) for v in past.get("ids", ())),
            }
        )
    return output


def _rule_newly_exposed_services(
    drift_result: DriftResult,
    history: Mapping[tuple[str, str], Mapping[str, Any]],
) -> list[dict[str, Any]]:
    del history
    output: list[dict[str, Any]] = []
    for item in drift_result.new:
        services = item.get("services")
        if not isinstance(services, list) or not services:
            continue
        service_refs = sorted(_service_reference(service) for service in services)
        output.append(
            {
                "rule_id": "newly_exposed_services",
                "title": "Review newly exposed services",
                "asset_uid": str(item.get("asset_uid", "unknown")),
                "summary": f"New asset exposes services requiring intent confirmation: {', '.join(service_refs)}.",
                "impact": 0.6,
                "risk": 0.7,
                "effort": 0.3,
                "confidence": 0.85,
                "evidence_discrepancy_ids": tuple(),
            }
        )
    return output


def _service_reference(service: object) -> str:
    if isinstance(service, Mapping):
        name = str(service.get("service_name") or service.get("name") or "service")
        protocol = str(service.get("protocol") or "tcp")
        port = service.get("port")
        if port is None:
            return f"{name}/{protocol}"
        return f"{name}:{port}/{protocol}"
    return str(service)
