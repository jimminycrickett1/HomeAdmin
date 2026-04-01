"""Recommendation generation contracts."""

from __future__ import annotations

import json
from pathlib import Path

from homeadmin.reporting import generate_recommendations, write_recommendation_reports
from homeadmin.config import AppConfig
from homeadmin.drift import DriftResult
from homeadmin.recommend import generate_ranked_recommendations


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


def test_ranked_recommendations_emit_rule_packs_and_stable_order() -> None:
    drift = DriftResult(
        reference_type="previous_run",
        reference_run_id=40,
        latest_run_id=42,
        generated_at="2026-03-29T10:00:00+00:00",
        current=[],
        new=[
            {
                "asset_uid": "asset-new-1",
                "services": [
                    {"service_name": "ssh", "port": 22, "protocol": "tcp"},
                ],
            }
        ],
        missing=[{"asset_uid": "asset-missing-1"}],
        unresolved_unknowns=[
            {
                "asset_uid": "asset-unk-1",
                "classification": "chronic_unknown",
                "age_days": 8,
                "recurrence_count": 3,
                "unknown_fingerprint": "unknown:asset-unk-1",
            }
        ],
        source_contradictions=[
            {
                "asset_uid": "asset-ctr-1",
                "contradictions": ["conflicting_ip_addresses"],
            }
        ],
    )

    discrepancy_records = [
        {"id": 10, "discrepancy_type": "source_contradiction", "fingerprint": "asset-ctr-1"},
        {"id": 11, "discrepancy_type": "source_contradiction", "fingerprint": "asset-ctr-1"},
        {"id": 20, "discrepancy_type": "unknown_backlog", "fingerprint": "unknown:asset-unk-1"},
        {"id": 30, "discrepancy_type": "missing_expected_asset_or_service", "fingerprint": "missing:asset-missing-1"},
        {"id": 31, "discrepancy_type": "missing_expected_asset_or_service", "fingerprint": "missing:asset-missing-1"},
    ]
    config = AppConfig(
        state_dir=Path(".homeadmin"),
        allowed_cidrs=(),
        arp_scan_interface=None,
        nmap_interface=None,
        arp_scan_max_seconds=120,
        nmap_max_rate=100,
    )

    ranked = generate_ranked_recommendations(drift, discrepancy_records, config=config)
    rule_ids = {item["rule_id"] for item in ranked}
    assert rule_ids == {
        "unresolved_unknowns",
        "source_contradictions",
        "repeated_missing_expected_assets_services",
        "newly_exposed_services",
    }
    assert [item["rank"] for item in ranked] == [1, 2, 3, 4]

    second = generate_ranked_recommendations(drift, discrepancy_records, config=config)
    assert [item["rule_id"] for item in ranked] == [item["rule_id"] for item in second]
    assert [item["asset_uid"] for item in ranked] == [item["asset_uid"] for item in second]
