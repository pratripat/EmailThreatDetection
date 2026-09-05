"""
Deterministic URL Feature Extractor Tests
Verifies that feature extraction, brand detection, and deterministic scoring
work 100% offline with zero network calls.
"""

import pytest
from src.url_analysis.features import extract_features, compute_deterministic_score
from src.url_analysis.extractor import extract_urls_from_text, extract_urls_from_html


def test_extract_urls_from_text():
    sample = "Check out https://example.com/login and http://test.org?q=1 for details."
    urls = extract_urls_from_text(sample)
    assert "https://example.com/login" in urls
    assert "http://test.org?q=1" in urls


def test_extract_urls_from_html():
    html = '<p>Click <a href="https://phish.xyz/auth">here</a> or see <img src="http://cdn.com/logo.png"></p>'
    urls = extract_urls_from_html(html)
    assert "https://phish.xyz/auth" in urls
    assert "http://cdn.com/logo.png" in urls


def test_benign_url_features():
    url = "https://www.google.com/search?q=cybersecurity"
    features = extract_features(url)
    assert features["has_https"] is True
    assert features["has_ip"] is False
    assert features["is_shortened"] is False
    assert features["suspicious_tld"] is False
    assert features["domain"] == "google.com"

    result = compute_deterministic_score(features)
    assert result["reputation"] == "SAFE"
    assert result["threatScore"] < 30


def test_malicious_ip_url_features():
    url = "http://192.168.1.50/login.php"
    features = extract_features(url)
    assert features["has_https"] is False
    assert features["has_ip"] is True
    assert "login" in features["sensitive_keywords"]

    result = compute_deterministic_score(features)
    assert result["threatScore"] >= 60
    assert result["reputation"] == "MALICIOUS"
    assert any("Direct IP address" in f for f in result["flags"])


def test_brand_typosquatting_detection():
    url = "http://paypa1-security.xyz/account/verify"
    features = extract_features(url)
    assert features["suspicious_tld"] is True
    assert len(features["brand_findings"]) > 0

    result = compute_deterministic_score(features)
    assert result["threatScore"] >= 60
    assert result["reputation"] == "MALICIOUS"


def test_punycode_and_shortener():
    url = "http://xn--pple-43d.com"
    features = extract_features(url)
    assert features["has_punycode"] is True
    result = compute_deterministic_score(features)
    assert any("Punycode" in f for f in result["flags"])

    short_url = "https://bit.ly/secure-login"
    features_short = extract_features(short_url)
    assert features_short["is_shortened"] is True
