"""Reporting helpers for JSON and Markdown outputs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
from typing import Any

from homeadmin.drift import DriftResult, drift_to_dict
from homeadmin.reporting.recommendations import (
    RecommendationArtifacts,
    generate_recommendations,
    write_recommendation_reports,
)


@dataclass(frozen=True, slots=True)
class ReportArtifacts:
    """Paths to report artifacts written to disk."""

    json_path: Path
    markdown_path: Path
    recommendations_json_path: Path
    recommendations_markdown_path: Path


def write_reports(result: DriftResult, output_dir: Path) -> ReportArtifacts:
    """Write JSON and Markdown report artifacts with explicit required sections."""
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = drift_to_dict(result)

    payload["unknown_count_by_age_bucket"] = _unknown_count_by_age_bucket(payload.get("unresolved_unknowns", []))
    payload["top_unresolved_unknowns"] = _top_unresolved_unknowns(payload.get("unresolved_unknowns", []))

    json_path = output_dir / "drift_report.json"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    markdown_path = output_dir / "drift_report.md"
    markdown_path.write_text(_render_markdown(payload), encoding="utf-8")

    recommendations = generate_recommendations(payload)
    recommendation_artifacts = write_recommendation_reports(recommendations, output_dir)

    return ReportArtifacts(
        json_path=json_path,
        markdown_path=markdown_path,
        recommendations_json_path=recommendation_artifacts.json_path,
        recommendations_markdown_path=recommendation_artifacts.markdown_path,
    )


def _render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# HomeAdmin Drift Report",
        "",
        f"- Generated at: `{payload['generated_at']}`",
        f"- Latest run id: `{payload['latest_run_id']}`",
        f"- Reference: `{payload['reference_type']}`",
        "",
        "## Current Assets",
        _render_asset_list(payload.get("current", [])),
        "",
        "## New Assets",
        _render_asset_list(payload.get("new", [])),
        "",
        "## Missing Assets",
        _render_asset_list(payload.get("missing", [])),
        "",
        "## Unresolved Unknowns",
        _render_asset_list(payload.get("unresolved_unknowns", [])),
        "",
        "## Unknown Count by Age Bucket",
        _render_age_bucket_list(payload.get("unknown_count_by_age_bucket", {})),
        "",
        "## Top Unresolved Unknowns Requiring Operator Input",
        _render_asset_list(payload.get("top_unresolved_unknowns", [])),
        "",
        "## Source Contradictions",
        _render_asset_list(payload.get("source_contradictions", [])),
        "",
    ]
    return "\n".join(lines)


def _render_asset_list(items: list[dict[str, Any]]) -> str:
    if not items:
        return "_None_"
    rendered: list[str] = []
    for item in items:
        uid = item.get("asset_uid", "unknown")
        ip = item.get("ip_address", "n/a")
        hostname = item.get("hostname", "n/a")
        status = item.get("status", "n/a")
        rendered.append(f"- `{uid}` | ip=`{ip}` hostname=`{hostname}` status=`{status}`")
        contradictions = item.get("contradictions")
        if contradictions:
            rendered.append(f"  - contradictions: {', '.join(str(c) for c in contradictions)}")
        if item.get("classification"):
            rendered.append(
                "  - unknown_backlog: "
                f"classification={item.get('classification')} "
                f"priority={item.get('priority', 'n/a')} "
                f"age_days={item.get('age_days', 'n/a')} "
                f"recurrence_count={item.get('recurrence_count', 'n/a')}"
            )
    return "\n".join(rendered)


def _unknown_age_bucket(age_days: int) -> str:
    if age_days <= 1:
        return "0-1d"
    if age_days <= 7:
        return "2-7d"
    if age_days <= 30:
        return "8-30d"
    return "31d+"


def _unknown_count_by_age_bucket(items: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"0-1d": 0, "2-7d": 0, "8-30d": 0, "31d+": 0}
    for item in items:
        age_days = int(item.get("age_days", 0) or 0)
        counts[_unknown_age_bucket(age_days)] += 1
    return counts


def _top_unresolved_unknowns(items: list[dict[str, Any]], *, limit: int = 5) -> list[dict[str, Any]]:
    ranked = sorted(
        items,
        key=lambda item: (
            0 if item.get("priority") == "high" else (1 if item.get("priority") == "medium" else 2),
            -int(item.get("recurrence_count", 0) or 0),
            -int(item.get("age_days", 0) or 0),
            str(item.get("asset_uid", "")),
        ),
    )
    return ranked[:limit]


def _render_age_bucket_list(buckets: dict[str, int]) -> str:
    if not buckets:
        return "_None_"
    ordered = ["0-1d", "2-7d", "8-30d", "31d+"]
    return "\n".join(f"- `{bucket}`: `{int(buckets.get(bucket, 0))}`" for bucket in ordered)


__all__ = [
    "ReportArtifacts",
    "RecommendationArtifacts",
    "write_reports",
    "generate_recommendations",
    "write_recommendation_reports",
]
