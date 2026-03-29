from homeadmin.drift import classify_drift


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
