from homeadmin.normalizers import normalize_hostname, normalize_mac, normalize_observation


def test_normalize_mac_and_hostname():
    assert normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert normalize_hostname(" Router.LOCAL. ") == "router.local"


def test_normalize_observation():
    raw = {"ip": " 192.168.1.10 ", "mac": "AA:BB:CC:DD:EE:FF", "hostname": "NAS."}
    normalized = normalize_observation(raw)
    assert normalized["ip"] == "192.168.1.10"
    assert normalized["mac"] == "aa:bb:cc:dd:ee:ff"
    assert normalized["hostname"] == "nas"
