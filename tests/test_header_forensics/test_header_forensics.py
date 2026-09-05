"""
Header Forensics Unit Tests
Tests Received header parsing, SPF/DKIM validation, anomaly detection, and scoring.
"""

import email
from src.header_forensics.parser import parse_received_header, extract_ip_candidates
from src.header_forensics.auth_trust import parse_auth_context, check_auth_results
from src.header_forensics.anomalies import detect_anomalies
from src.header_forensics.scoring import compute_risk_score


def test_parse_received_header():
    raw_header = "from mail.sender.com ([192.0.2.1]) by mx.receiver.com with ESMTP; Fri, 01 Jan 2026 12:00:00 +0000"
    hop = parse_received_header(raw_header)
    assert "mail.sender.com" in hop.from_host
    assert hop.by_host == "mx.receiver.com"
    assert hop.with_protocol == "ESMTP"
    assert "2026" in hop.timestamp


def test_extract_ip_candidates():
    text = "Received: from mail.example.com ([198.51.100.4]) by relay.example.org with [2001:db8::1]"
    ips = extract_ip_candidates(text)
    assert "198.51.100.4" in ips
    assert "2001:db8::1" in ips


def test_auth_results_fail():
    raw_eml = """From: security@paypal.com
To: victim@example.com
Subject: Account Alert
Authentication-Results: mx.google.com; spf=fail (google.com: domain does not designate 192.0.2.1 as permitted sender); dkim=fail; dmarc=fail action=quarantine

Please verify your account.
"""
    msg = email.message_from_string(raw_eml)
    ctx = parse_auth_context(msg, relay_chain=[])
    auth = check_auth_results(ctx)
    assert auth["spf"] == "fail"
    assert auth["dkim"] == "fail"
    assert auth["dmarc"] == "fail"

    anomalies, _, _ = detect_anomalies(msg, [], auth)
    assert any("SPF" in a for a in anomalies)
    assert any("DKIM" in a for a in anomalies)

    score = compute_risk_score(anomalies, auth)
    assert score >= 40
