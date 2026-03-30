"""Reconcile workflow persistence contracts."""

from __future__ import annotations

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
                "arp_scan": {"ip_address": "192.168.1.10", "mac_address": "aa:bb:cc:dd:ee:01"},
                "nmap": {"ip_address": "192.168.1.10", "mac_address": "aa:bb:cc:dd:ee:02"},
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
        "SELECT observation_key FROM observations WHERE run_id = ? AND observation_type = 'asset_snapshot'",
        (result.run_id,),
    ).fetchone()
    assert snapshot_row is not None
    assert str(snapshot_row["observation_key"]).startswith("mac:")
