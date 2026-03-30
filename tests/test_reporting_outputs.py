"""Reporting output determinism contracts."""

from __future__ import annotations

from homeadmin.drift.workflow import DriftResult
from homeadmin.reporting import write_reports


def test_write_reports_generates_expected_sections(tmp_path) -> None:
    result = DriftResult(
        reference_type="previous_run",
        reference_run_id=1,
        latest_run_id=2,
        generated_at="2026-03-29T00:00:00+00:00",
        current=[{"asset_uid": "asset-a", "ip_address": "192.168.1.10", "hostname": "a.local", "status": "active"}],
        new=[{"asset_uid": "asset-b", "ip_address": "192.168.1.11", "hostname": "b.local", "status": "active"}],
        missing=[{"asset_uid": "asset-c", "ip_address": "192.168.1.12", "hostname": "c.local", "status": "missing"}],
        unresolved_unknowns=[],
        source_contradictions=[{"asset_uid": "asset-d", "ip_address": "192.168.1.13", "hostname": "d.local", "status": "active", "contradictions": ["conflicting_ip_addresses"]}],
    )

    artifacts = write_reports(result, tmp_path)

    markdown = artifacts.markdown_path.read_text(encoding="utf-8")
    assert "## Current Assets" in markdown
    assert "## New Assets" in markdown
    assert "## Missing Assets" in markdown
    assert "## Unresolved Unknowns" in markdown
    assert "## Source Contradictions" in markdown
    assert "contradictions: conflicting_ip_addresses" in markdown
