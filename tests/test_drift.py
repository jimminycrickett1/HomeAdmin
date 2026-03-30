from homeadmin.drift import calculate_drift, classify_drift
from homeadmin.reconcile.workflow import reconcile_assets
from homeadmin.storage import Storage


def test_drift_classification_includes_requested_blind_spots():
    baseline = [
        {
            "identity_key": "mac:aa:bb:cc:dd:ee:ff",
            "ip": "192.168.1.10",
            "hostname": "nas.local",
            "services": [{"port": 22, "protocol": "tcp", "service_name": "ssh"}],
        }
    ]
    observed = [
        {
            "identity_key": "mac:aa:bb:cc:dd:ee:ff",
            "ip": "192.168.1.20",
            "hostname": None,
            "services": [{"port": 22, "protocol": "tcp", "service_name": "ssh"}],
        },
        {
            "identity_key": "mac:11:22:33:44:55:66",
            "ip": "192.168.1.40",
            "hostname": "printer.local",
            "services": [],
        },
    ]

    findings = classify_drift(
        baseline_assets=baseline,
        observed_assets=observed,
        network_visibility_complete=False,
        scan_profile="safe",
    )
    classifications = {item["classification"] for item in findings}

    assert "ip_churn" in classifications
    assert "identity_ambiguity" in classifications
    assert "new_asset" in classifications
    assert "incomplete_network_visibility" in classifications
    assert "scan_sensitivity" in classifications


def test_sleeping_device_classification():
    findings = classify_drift(
        baseline_assets=[{"identity_key": "mac:aa:bb:cc:dd:ee:ff", "ip": "192.168.1.10"}],
        observed_assets=[],
        network_visibility_complete=True,
        scan_profile="default",
    )
    assert findings == [
        {"identity_key": "mac:aa:bb:cc:dd:ee:ff", "classification": "sleeping_device_or_offline"}
    ]


def test_unknowns_are_classified_as_new_then_chronic(tmp_path) -> None:
    storage = Storage(tmp_path / "state.db")
    storage.initialize()

    unknown_asset = {"asset_uid": "asset-unknown", "ip_address": "192.168.1.80"}

    reconcile_assets(storage, [unknown_asset], run_uuid="reconcile-1")
    first = calculate_drift(storage)

    reconcile_assets(storage, [unknown_asset], run_uuid="reconcile-2")
    second = calculate_drift(storage)

    reconcile_assets(storage, [unknown_asset], run_uuid="reconcile-3")
    third = calculate_drift(storage)

    assert first.unresolved_unknowns[0]["classification"] == "new_unknown"
    assert first.unresolved_unknowns[0]["priority"] == "low"

    assert second.unresolved_unknowns[0]["classification"] == "new_unknown"
    assert second.unresolved_unknowns[0]["priority"] == "medium"

    assert third.unresolved_unknowns[0]["classification"] == "chronic_unknown"
    assert third.unresolved_unknowns[0]["priority"] == "high"

    escalated_count = storage.connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM discrepancies
        WHERE discrepancy_type = 'unknown_backlog' AND status = 'escalated'
        """
    ).fetchone()["count"]
    assert int(escalated_count) >= 1
