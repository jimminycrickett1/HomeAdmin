"""Reporting helpers for JSON and Markdown outputs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
from typing import Any

from homeadmin.drift import DriftResult, drift_to_dict


@dataclass(frozen=True, slots=True)
class ReportArtifacts:
    """Paths to report artifacts written to disk."""

    json_path: Path
    markdown_path: Path


def write_reports(result: DriftResult, output_dir: Path) -> ReportArtifacts:
    """Write JSON and Markdown report artifacts with explicit required sections."""
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = drift_to_dict(result)

    json_path = output_dir / "drift_report.json"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    markdown_path = output_dir / "drift_report.md"
    markdown_path.write_text(_render_markdown(payload), encoding="utf-8")

    return ReportArtifacts(json_path=json_path, markdown_path=markdown_path)


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
    return "\n".join(rendered)
