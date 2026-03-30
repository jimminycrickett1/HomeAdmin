"""Recommendation generation contracts."""

from __future__ import annotations

import json
from pathlib import Path

from homeadmin.reporting import generate_recommendations, write_recommendation_reports


def test_generate_recommendations_from_fixture_payload() -> None:
    fixture_path = Path(__file__).parent / "fixtures" / "drift" / "recommendation_input.json"
    payload = json.loads(fixture_path.read_text(encoding="utf-8"))

    recommendations = generate_recommendations(payload)

    assert recommendations["source_run_id"] == 42
    assert recommendations["recommendation_count"] == 4

    by_rule = {item["rule_id"]: item for item in recommendations["recommendations"]}

    exposed = by_rule["exposed_services_without_baseline_expectations"]
    assert exposed["asset_uid"] == "asset-new-1"
    assert "ssh:22/tcp" in exposed["opportunity"]["services"]
    assert exposed["provenance"]["source_run_id"] == 42
    assert "source_observation:arp_scan" in exposed["provenance"]["observation_references"]

    contradictions = by_rule["repeated_identity_evidence_contradictions"]
    assert contradictions["opportunity"]["recurrence_count"] == 3
    assert contradictions["provenance"]["discrepancy_ids"] == ["2201", "2202"]

    missing = by_rule["assets_missing_expected_services"]
    assert missing["provenance"]["discrepancy_ids"] == ["3101"]

    unknown = by_rule["stale_unknown_assets"]
    assert unknown["priority"] == "high"
    assert unknown["provenance"]["discrepancy_ids"] == ["4101"]


def test_write_recommendation_reports_outputs_json_and_markdown(tmp_path: Path) -> None:
    fixture_path = Path(__file__).parent / "fixtures" / "drift" / "recommendation_input.json"
    payload = json.loads(fixture_path.read_text(encoding="utf-8"))
    recommendations = generate_recommendations(payload)

    artifacts = write_recommendation_reports(recommendations, tmp_path)

    serialized = json.loads(artifacts.json_path.read_text(encoding="utf-8"))
    assert serialized["recommendation_count"] == 4

    markdown = artifacts.markdown_path.read_text(encoding="utf-8")
    assert "# HomeAdmin Recommendation Report" in markdown
    assert "## Actionable Opportunities" in markdown
    assert "`2201`" in markdown
    assert "source_observation:arp_scan" in markdown
