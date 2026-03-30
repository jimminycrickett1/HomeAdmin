"""Recommendation generation and reporting from drift payloads."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class RecommendationArtifacts:
    """Paths to recommendation artifacts written to disk."""

    json_path: Path
    markdown_path: Path


def generate_recommendations(drift_payload: Mapping[str, Any]) -> dict[str, Any]:
    """Generate conservative actionable opportunities from drift output."""
    latest_run_id = int(drift_payload.get("latest_run_id", 0) or 0)

    recommendations: list[dict[str, Any]] = []
    recommendations.extend(_recommend_exposed_services(drift_payload, latest_run_id))
    recommendations.extend(_recommend_repeated_contradictions(drift_payload, latest_run_id))
    recommendations.extend(_recommend_missing_expected_services(drift_payload, latest_run_id))
    recommendations.extend(_recommend_stale_unknown_assets(drift_payload, latest_run_id))

    return {
        "generated_at": drift_payload.get("generated_at"),
        "source_run_id": latest_run_id,
        "recommendation_count": len(recommendations),
        "recommendations": recommendations,
    }


def write_recommendation_reports(payload: Mapping[str, Any], output_dir: Path) -> RecommendationArtifacts:
    """Write recommendation reports as JSON and Markdown."""
    output_dir.mkdir(parents=True, exist_ok=True)

    json_path = output_dir / "recommendations_report.json"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    markdown_path = output_dir / "recommendations_report.md"
    markdown_path.write_text(_render_recommendations_markdown(payload), encoding="utf-8")

    return RecommendationArtifacts(json_path=json_path, markdown_path=markdown_path)


def _recommend_exposed_services(drift_payload: Mapping[str, Any], run_id: int) -> list[dict[str, Any]]:
    opportunities: list[dict[str, Any]] = []
    for asset in drift_payload.get("new", []):
        if not isinstance(asset, Mapping):
            continue
        services = _service_refs(asset)
        if not services:
            continue
        opportunities.append(
            {
                "rule_id": "exposed_services_without_baseline_expectations",
                "title": "Review exposed services on newly observed asset",
                "priority": "medium",
                "asset_uid": str(asset.get("asset_uid", "unknown")),
                "summary": "Asset exposes services without existing baseline expectations; confirm intended exposure before baselining.",
                "opportunity": {"services": services},
                "provenance": _provenance(asset, run_id, default_discrepancy=f"new:{asset.get('asset_uid', 'unknown')}"),
            }
        )
    return opportunities


def _recommend_repeated_contradictions(drift_payload: Mapping[str, Any], run_id: int) -> list[dict[str, Any]]:
    opportunities: list[dict[str, Any]] = []
    by_asset: dict[str, int] = {}
    for item in drift_payload.get("source_contradictions", []):
        if isinstance(item, Mapping):
            asset_uid = str(item.get("asset_uid", "unknown"))
            by_asset[asset_uid] = by_asset.get(asset_uid, 0) + 1

    for item in drift_payload.get("source_contradictions", []):
        if not isinstance(item, Mapping):
            continue
        asset_uid = str(item.get("asset_uid", "unknown"))
        explicit_count = int(item.get("contradiction_recurrence_count", 0) or 0)
        observed_count = max(explicit_count, by_asset.get(asset_uid, 0))
        if observed_count < 2:
            continue
        contradictions = [str(value) for value in item.get("contradictions", [])]
        opportunities.append(
            {
                "rule_id": "repeated_identity_evidence_contradictions",
                "title": "Escalate repeated identity contradictions",
                "priority": "high",
                "asset_uid": asset_uid,
                "summary": "Identity evidence contradictions repeated across observations; validate collector quality and identity resolution confidence.",
                "opportunity": {
                    "contradictions": contradictions,
                    "recurrence_count": observed_count,
                },
                "provenance": _provenance(item, run_id, default_discrepancy=f"contradiction:{asset_uid}"),
            }
        )
    return opportunities


def _recommend_missing_expected_services(drift_payload: Mapping[str, Any], run_id: int) -> list[dict[str, Any]]:
    opportunities: list[dict[str, Any]] = []
    for asset in drift_payload.get("missing", []):
        if not isinstance(asset, Mapping):
            continue
        services = _service_refs(asset)
        if not services:
            continue
        opportunities.append(
            {
                "rule_id": "assets_missing_expected_services",
                "title": "Investigate missing asset services",
                "priority": "high",
                "asset_uid": str(asset.get("asset_uid", "unknown")),
                "summary": "Asset expected by reference is absent along with expected services; validate outage, retirement, or visibility gap.",
                "opportunity": {"expected_services": services},
                "provenance": _provenance(asset, run_id, default_discrepancy=f"missing:{asset.get('asset_uid', 'unknown')}"),
            }
        )
    return opportunities


def _recommend_stale_unknown_assets(drift_payload: Mapping[str, Any], run_id: int) -> list[dict[str, Any]]:
    opportunities: list[dict[str, Any]] = []
    for asset in drift_payload.get("unresolved_unknowns", []):
        if not isinstance(asset, Mapping):
            continue
        age_days = int(asset.get("age_days", 0) or 0)
        recurrence_count = int(asset.get("recurrence_count", 0) or 0)
        classification = str(asset.get("classification", ""))
        is_stale = classification == "chronic_unknown" or age_days >= 7 or recurrence_count >= 3
        if not is_stale:
            continue
        opportunities.append(
            {
                "rule_id": "stale_unknown_assets",
                "title": "Triage stale unknown asset",
                "priority": "high" if classification == "chronic_unknown" else "medium",
                "asset_uid": str(asset.get("asset_uid", "unknown")),
                "summary": "Unknown asset has persisted and requires operator triage for identification or suppression policy.",
                "opportunity": {
                    "classification": classification,
                    "age_days": age_days,
                    "recurrence_count": recurrence_count,
                },
                "provenance": _provenance(
                    asset,
                    run_id,
                    default_discrepancy=f"unknown:{asset.get('unknown_fingerprint') or asset.get('asset_uid', 'unknown')}",
                ),
            }
        )
    return opportunities


def _service_refs(asset: Mapping[str, Any]) -> list[str]:
    services = asset.get("services")
    if not isinstance(services, list):
        return []
    refs: list[str] = []
    for svc in services:
        if isinstance(svc, Mapping):
            port = svc.get("port")
            protocol = str(svc.get("protocol", "tcp"))
            name = str(svc.get("service_name") or svc.get("name") or "service")
            if port is None:
                refs.append(f"{name}/{protocol}")
            else:
                refs.append(f"{name}:{port}/{protocol}")
        else:
            refs.append(str(svc))
    return sorted(set(refs))


def _provenance(item: Mapping[str, Any], run_id: int, *, default_discrepancy: str) -> dict[str, Any]:
    discrepancy_ids: list[str] = []
    if isinstance(item.get("discrepancy_ids"), list):
        discrepancy_ids.extend(str(value) for value in item["discrepancy_ids"])
    if item.get("discrepancy_id") is not None:
        discrepancy_ids.append(str(item["discrepancy_id"]))
    if not discrepancy_ids:
        discrepancy_ids.append(default_discrepancy)

    observation_refs = _observation_refs(item)
    return {
        "source_run_id": run_id,
        "discrepancy_ids": sorted(set(discrepancy_ids)),
        "observation_references": observation_refs,
    }


def _observation_refs(item: Mapping[str, Any]) -> list[str]:
    refs: list[str] = []

    provenance = item.get("provenance")
    if isinstance(provenance, Mapping):
        keys = provenance.get("source_observation_keys")
        if isinstance(keys, list):
            refs.extend(f"source_observation:{key}" for key in keys)
        raw_artifacts = provenance.get("raw_artifacts")
        if isinstance(raw_artifacts, list):
            for artifact in raw_artifacts:
                if not isinstance(artifact, Mapping):
                    continue
                path = str(artifact.get("raw_artifact_path") or "").strip()
                digest = str(artifact.get("raw_artifact_hash") or "").strip()
                if path or digest:
                    refs.append(f"artifact:{path}#{digest}")

    source_observations = item.get("source_observations")
    if isinstance(source_observations, Mapping):
        refs.extend(f"source_observation:{name}" for name in source_observations.keys())

    return sorted(set(refs))


def _render_recommendations_markdown(payload: Mapping[str, Any]) -> str:
    lines = [
        "# HomeAdmin Recommendation Report",
        "",
        f"- Generated at: `{payload.get('generated_at', 'n/a')}`",
        f"- Source run id: `{payload.get('source_run_id', 'n/a')}`",
        f"- Recommendation count: `{payload.get('recommendation_count', 0)}`",
        "",
        "## Actionable Opportunities",
    ]

    recommendations = payload.get("recommendations")
    if not isinstance(recommendations, list) or not recommendations:
        lines.append("_None_")
        return "\n".join(lines)

    for item in recommendations:
        if not isinstance(item, Mapping):
            continue
        lines.append(
            f"- **{item.get('title', 'Recommendation')}** "
            f"(rule=`{item.get('rule_id', 'n/a')}`, priority=`{item.get('priority', 'n/a')}`, asset=`{item.get('asset_uid', 'unknown')}`)"
        )
        lines.append(f"  - summary: {item.get('summary', '')}")
        provenance = item.get("provenance", {})
        lines.append(f"  - source_run_id: `{provenance.get('source_run_id', 'n/a')}`")
        lines.append(
            "  - discrepancy_ids: "
            + ", ".join(f"`{value}`" for value in provenance.get("discrepancy_ids", []))
        )
        lines.append(
            "  - observation_references: "
            + ", ".join(f"`{value}`" for value in provenance.get("observation_references", []))
        )

    return "\n".join(lines)
