"""Drift classification helpers."""

from __future__ import annotations


def classify_drift(
    *,
    baseline_assets: list[dict[str, object]],
    observed_assets: list[dict[str, object]],
    network_visibility_complete: bool,
    scan_profile: str,
) -> list[dict[str, object]]:
    """Classify differences between baseline and current observations."""
    baseline_by_key = {item["identity_key"]: item for item in baseline_assets if "identity_key" in item}
    observed_by_key = {item["identity_key"]: item for item in observed_assets if "identity_key" in item}

    findings: list[dict[str, object]] = []

    for key, baseline in baseline_by_key.items():
        observed = observed_by_key.get(key)
        if observed is None:
            findings.append({"identity_key": key, "classification": "sleeping_device_or_offline"})
            continue

        baseline_ip = baseline.get("ip")
        observed_ip = observed.get("ip")
        if baseline_ip and observed_ip and baseline_ip != observed_ip:
            findings.append({"identity_key": key, "classification": "ip_churn"})

        if baseline.get("hostname") and observed.get("hostname") is None:
            findings.append({"identity_key": key, "classification": "identity_ambiguity"})

        if baseline.get("services") != observed.get("services"):
            findings.append({"identity_key": key, "classification": "service_drift"})

    for key in observed_by_key:
        if key not in baseline_by_key:
            findings.append({"identity_key": key, "classification": "new_asset"})

    if not network_visibility_complete:
        findings.append({"identity_key": "_global", "classification": "incomplete_network_visibility"})

    if scan_profile.lower() in {"safe", "low-intensity"}:
        findings.append({"identity_key": "_global", "classification": "scan_sensitivity"})

    return findings
