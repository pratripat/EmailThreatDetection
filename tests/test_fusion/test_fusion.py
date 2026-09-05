"""
Hybrid Threat Score Fusion Tests
Tests multi-vector score blending, evidence escalation rules, and tier classification.
"""

from src.fusion.hybrid_score import fuse_threat_intelligence, classify_tier


def test_classify_tier():
    assert classify_tier(95) == "CRITICAL"
    assert classify_tier(75) == "HIGH"
    assert classify_tier(50) == "SUSPICIOUS"
    assert classify_tier(10) == "LOW"


def test_fusion_escalation_on_malicious_url():
    header_data = {"risk_score": 10, "anomalies": []}
    origin_data = {"risk_score": 0, "is_vpn": False, "is_datacenter": False}
    url_data = {
        "max_threat_score": 90,
        "malicious_count": 1,
        "suspicious_count": 0,
        "analyzed_urls": [{
            "url": "http://evil-phish.xyz",
            "reputation": "MALICIOUS",
            "threatScore": 90,
            "flags": ["Malicious URL"]
        }]
    }

    fusion = fuse_threat_intelligence(header_data, origin_data, url_data)
    assert fusion["final_threat_score"] >= 85
    assert fusion["threat_tier"] in ["CRITICAL", "HIGH"]
    assert "Malicious URL" in fusion["primary_threat_vector"]


def test_fusion_clean_email():
    header_data = {"risk_score": 0, "anomalies": []}
    origin_data = {"risk_score": 0, "is_vpn": False}
    url_data = {
        "max_threat_score": 5,
        "malicious_count": 0,
        "suspicious_count": 0,
        "analyzed_urls": [{
            "url": "https://google.com",
            "reputation": "SAFE",
            "threatScore": 5,
            "flags": []
        }]
    }

    fusion = fuse_threat_intelligence(header_data, origin_data, url_data)
    assert fusion["final_threat_score"] < 40
    assert fusion["threat_tier"] == "LOW"
