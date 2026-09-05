"""
Grok AI Client & Circuit Breaker Unit Tests
Uses mocked OpenAI client to guarantee zero live network traffic during testing.
"""

from unittest.mock import MagicMock, patch
from pathlib import Path
import pytest
from src.url_analysis.grok_client import GrokClient, CircuitBreakerState, GrokUnavailableError
from src.url_analysis.prompts import parse_grok_response, build_analysis_prompt
from src.url_analysis.analyzer import URLAnalyzer
from src.url_analysis.cache import URLCache


def test_parse_grok_response_key_value():
    raw_text = """
    VERDICT: PHISHING
    CONFIDENCE: 0.95
    REASON: Targets PayPal credentials with deceptive typo domain.
    FLAGS: Homoglyph, Credential Form
    """
    parsed = parse_grok_response(raw_text)
    assert parsed["verdict"] == "PHISHING"
    assert parsed["confidence"] == 0.95
    assert "PayPal" in parsed["reason"]
    assert "Homoglyph" in parsed["flags"]


def test_parse_grok_response_json():
    raw_json = '{"verdict": "MALICIOUS", "confidence": 0.88, "reason": "Direct malware binary host", "flags": ["Executable", "Direct IP"]}'
    parsed = parse_grok_response(raw_json)
    assert parsed["verdict"] == "MALICIOUS"
    assert parsed["confidence"] == 0.88
    assert "Direct malware" in parsed["reason"]
    assert "Direct IP" in parsed["flags"]


def test_grok_client_offline_when_no_key():
    client = GrokClient(api_key="")
    assert client.is_available is False

    with pytest.raises(GrokUnavailableError):
        client.analyze("https://test.com", {})


def test_grok_client_circuit_breaker_trips():
    mock_openai = MagicMock()
    mock_openai.chat.completions.create.side_effect = Exception("API connection timed out")

    client = GrokClient(api_key="xai-test-dummy-key")
    client.client = mock_openai
    client.failure_threshold = 2
    client.max_retries = 0

    assert client.state == CircuitBreakerState.CLOSED

    # Failure 1
    with pytest.raises(GrokUnavailableError):
        client.analyze("https://test1.com", {})
    assert client.state == CircuitBreakerState.CLOSED

    # Failure 2 -> Should trip breaker
    with pytest.raises(GrokUnavailableError):
        client.analyze("https://test2.com", {})
    assert client.state == CircuitBreakerState.OPEN
    assert client.is_available is False


def test_analyzer_orchestrator_mocked(tmp_path):
    mock_grok = MagicMock()
    mock_grok.analyze.return_value = {
        "verdict": "PHISHING",
        "confidence": 0.92,
        "reason": "Phishing site impersonating Chase Bank",
        "flags": ["Chase Impersonation"]
    }

    cache = URLCache(db_path=tmp_path / "temp_cache.sqlite")
    analyzer = URLAnalyzer(grok_client=mock_grok, cache=cache, use_cache=False)

    res = analyzer.analyze_url("https://chase-update-account.com/login")
    assert res["reputation"] == "MALICIOUS"
    assert res["threatScore"] >= 80
    assert res["grok_analysis"]["verdict"] == "PHISHING"
    assert "Chase Impersonation" in " ".join(res["flags"])
