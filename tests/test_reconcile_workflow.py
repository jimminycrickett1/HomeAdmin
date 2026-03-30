"""Reconcile workflow persistence contracts."""

from __future__ import annotations

import json

from homeadmin.reconcile.workflow import reconcile_assets
from homeadmin.storage import Storage


def test_reconcile_persists_identities_and_contradictions(tmp_path) -> None:
    storage = Storage(tmp_path / "state.db")
    storage.initialize()

    assets = [
        {
            "asset_uid": "asset-1",
            "ip_address": "192.168.1.10",
            "source_observations": {
                "arp_scan": {
                    "ip_address": "192.168.1.10",
                    "mac_address": "aa:bb:cc:dd:ee:01",
                    "raw_artifact_path": "artifacts/arp.out",
                    "raw_artifact_hash": "hash-arp",
                },
                "nmap": {
                    "ip_address": "192.168.1.10",
                    "mac_address": "aa:bb:cc:dd:ee:02",
                    "raw_artifact_path": "artifacts/nmap.out",
                    "raw_artifact_hash": "hash-nmap",
                },
            },
        }
    ]

    result = reconcile_assets(storage, assets, run_uuid="reconcile-run")

    assert result.asset_count == 1

    identity_count = storage.connection.execute("SELECT COUNT(*) AS count FROM identities").fetchone()["count"]
    assert int(identity_count) == 1

    discrepancy_count = storage.connection.execute(
        "SELECT COUNT(*) AS count FROM discrepancies WHERE discrepancy_type = 'reconcile_contradiction'"
    ).fetchone()["count"]
    assert int(discrepancy_count) == 1

    snapshot_row = storage.connection.execute(
        "SELECT observation_key, observation_value FROM observations WHERE run_id = ? AND observation_type = 'asset_snapshot'",
        (result.run_id,),
    ).fetchone()
    assert snapshot_row is not None
    assert str(snapshot_row["observation_key"]).startswith("mac:")
    snapshot_payload = json.loads(str(snapshot_row["observation_value"]))
    assert snapshot_payload["provenance"]["source_observation_keys"] == ["arp_scan", "nmap"]


def test_reconcile_high_confidence_mac_merge_records_evidence(tmp_path) -> None:
    storage = Storage(tmp_path / "state.db")
    storage.initialize()

    assets = [
        {
            "asset_uid": "asset-mac-high",
            "source_observations": {
                "arp_scan": {
                    "ip_address": "192.168.1.31",
                    "mac_address": "aa:bb:cc:dd:ee:31",
                    "hostname": "storage.home",
                    "raw_artifact_path": "artifacts/arp-31.out",
                    "raw_artifact_hash": "hash-31-arp",
                },
                "nmap": {
                    "ip_address": "192.168.1.31",
                    "mac_address": "aa:bb:cc:dd:ee:31",
                    "hostname": "storage.home",
                    "services": [
                        {"port": 22, "protocol": "tcp", "service_name": "ssh"},
                        {"port": 443, "protocol": "tcp", "service_name": "https"},
                    ],
                    "raw_artifact_path": "artifacts/nmap-31.out",
                    "raw_artifact_hash": "hash-31-nmap",
                },
            },
        }
    ]

    result = reconcile_assets(storage, assets, run_uuid="reconcile-mac-high")

    row = storage.connection.execute(
        "SELECT id, confidence, raw_artifact_path FROM identities WHERE identity_uid = 'mac:aa:bb:cc:dd:ee:31'"
    ).fetchone()
    assert row is not None
    assert float(row["confidence"]) >= 0.8
    assert "artifacts/arp-31.out" in str(row["raw_artifact_path"])
    assert "artifacts/nmap-31.out" in str(row["raw_artifact_path"])

    evidence_count = storage.connection.execute(
        "SELECT COUNT(*) AS count FROM identity_evidence WHERE run_id = ?",
        (result.run_id,),
    ).fetchone()["count"]
    assert int(evidence_count) >= 5


def test_reconcile_low_confidence_ip_only_merge(tmp_path) -> None:
    storage = Storage(tmp_path / "state.db")
    storage.initialize()

    assets = [
        {
            "asset_uid": "asset-ip-low",
            "ip_address": "192.168.1.90",
            "source_observations": {
                "arp_scan": {
                    "ip_address": "192.168.1.90",
                    "raw_artifact_path": "artifacts/arp-90.out",
                    "raw_artifact_hash": "hash-90-arp",
                }
            },
        }
    ]

    reconcile_assets(storage, assets, run_uuid="reconcile-ip-low")

    row = storage.connection.execute(
        "SELECT confidence FROM identities WHERE identity_uid = 'ip:192.168.1.90'"
    ).fetchone()
    assert row is not None
    assert float(row["confidence"]) <= 0.3


def test_reconcile_confidence_drops_on_contradictory_evidence(tmp_path) -> None:
    storage = Storage(tmp_path / "state.db")
    storage.initialize()

    assets = [
        {
            "asset_uid": "asset-conflict",
            "source_observations": {
                "arp_scan": {
                    "ip_address": "192.168.1.44",
                    "mac_address": "aa:bb:cc:dd:ee:44",
                    "hostname": "printer.home",
                },
                "nmap": {
                    "ip_address": "192.168.1.44",
                    "mac_address": "aa:bb:cc:dd:ee:45",
                    "hostname": "printer.home",
                },
            },
        }
    ]

    result = reconcile_assets(storage, assets, run_uuid="reconcile-conflict")

    identity_row = storage.connection.execute(
        "SELECT id, confidence FROM identities WHERE identity_uid = 'mac:aa:bb:cc:dd:ee:44'"
    ).fetchone()
    assert identity_row is not None
    assert float(identity_row["confidence"]) < 0.6

    penalty_row = storage.connection.execute(
        "SELECT contribution FROM identity_evidence WHERE run_id = ? AND evidence_type = 'contradiction_penalty'",
        (result.run_id,),
    ).fetchone()
    assert penalty_row is not None
    assert float(penalty_row["contribution"]) < 0.0
