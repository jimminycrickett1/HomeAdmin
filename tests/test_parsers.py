from homeadmin.collectors.arp_scan import parse_arp_scan_output
from homeadmin.collectors.nmap import parse_nmap_gnmap_output


def test_parse_arp_scan_output():
    raw = """Interface: eth0\nStarting arp-scan\n192.168.1.10\tAA:BB:CC:DD:EE:FF\tVendor A\n192.168.1.20\t11:22:33:44:55:66\tVendor B\nEnding arp-scan\n"""
    parsed = parse_arp_scan_output(raw)
    assert parsed == [
        {"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF", "vendor": "Vendor A"},
        {"ip": "192.168.1.20", "mac": "11:22:33:44:55:66", "vendor": "Vendor B"},
    ]


def test_parse_nmap_gnmap_output():
    raw = (
        "Host: 192.168.1.10 () Ports: 22/open/tcp//ssh///, 80/closed/tcp//http///\n"
        "Host: 192.168.1.20 () Ports: 53/open/udp//domain///\n"
    )
    parsed = parse_nmap_gnmap_output(raw)
    assert parsed == [
        {
            "ip": "192.168.1.10",
            "services": [{"port": 22, "protocol": "tcp", "service_name": "ssh"}],
        },
        {
            "ip": "192.168.1.20",
            "services": [{"port": 53, "protocol": "udp", "service_name": "domain"}],
        },
    ]
