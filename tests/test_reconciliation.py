from homeadmin.reconcile import merge_observations


def test_reconciliation_merges_sources_by_mac():
    arp = [{"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF", "hostname": "nas.local"}]
    nmap = [
        {
            "ip": "192.168.1.10",
            "mac": "aa:bb:cc:dd:ee:ff",
            "service": {"port": 22, "protocol": "tcp", "service_name": "ssh"},
        }
    ]

    merged = merge_observations(arp, nmap)
    assert len(merged) == 1
    record = merged[0]
    assert record["identity_key"] == "mac:aa:bb:cc:dd:ee:ff"
    assert record["sources"] == ["arp-scan", "nmap"]
    assert record["services"] == [{"port": 22, "protocol": "tcp", "service_name": "ssh"}]
