"""
Origin Infrastructure Analysis Tests
Tests IPv4/IPv6 classification and binary search CIDR range evaluation.
"""

import ipaddress
from src.origin_analysis.ip_classifier import classify_ip_type
from src.origin_analysis.range_lookup import build_bisect_index, check_ip_in_indexed_ranges
from src.origin_analysis.analyzer import OriginAnalyzer


def test_classify_ip_type():
    assert classify_ip_type("127.0.0.1") == "loopback"
    assert classify_ip_type("10.0.0.1") == "private"
    assert classify_ip_type("192.168.1.1") == "private"
    assert classify_ip_type("8.8.8.8") == "global"
    assert classify_ip_type("2001:4860:4860::8888") == "global"
    assert classify_ip_type("invalid-ip") == "invalid"


def test_bisect_range_lookup():
    networks = [
        ipaddress.ip_network("185.220.100.0/22"),
        ipaddress.ip_network("45.154.255.0/24"),
    ]
    indexed, starts = build_bisect_index(networks, version=4)

    target_hit = ipaddress.ip_address("185.220.101.45")
    match = check_ip_in_indexed_ranges(target_hit, indexed, starts)
    assert match == "185.220.100.0/22"

    target_miss = ipaddress.ip_address("8.8.8.8")
    assert check_ip_in_indexed_ranges(target_miss, indexed, starts) is None


def test_origin_analyzer_datacenter_and_vpn():
    analyzer = OriginAnalyzer()
    res_vpn = analyzer.analyze("185.220.101.5")
    assert res_vpn["valid"] is True
    assert res_vpn["is_vpn"] is True
    assert res_vpn["risk_score"] > 0

    res_clean = analyzer.analyze("142.250.190.46")  # Google IP
    assert res_clean["valid"] is True
    assert res_clean["classification"] == "global"
