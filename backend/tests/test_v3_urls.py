import socket
from unittest.mock import patch, MagicMock
from backend.app.intelligence.url_reputation import URLReputationService, url_to_vt_id
from backend.app.intelligence.redirect_analyzer import RedirectAnalyzer, check_url_ssrf_safety
from backend.app.intelligence.models import ProvenanceType


def test_url_to_vt_id():
    # Base64url encoding without trailing padding '='
    vt_id = url_to_vt_id("http://example.com/login")
    assert "=" not in vt_id
    assert len(vt_id) > 0


def test_ssrf_blocks_private_and_metadata_ips():
    # Direct IP literals
    safe, reason, is_ssrf = check_url_ssrf_safety("http://127.0.0.1/admin")
    assert not safe
    assert is_ssrf is True
    assert "Loopback" in reason

    safe, reason, is_ssrf = check_url_ssrf_safety("http://169.254.169.254/latest/meta-data/")
    assert not safe
    assert is_ssrf is True
    assert "Metadata" in reason

    safe, reason, is_ssrf = check_url_ssrf_safety("http://10.0.0.1/internal-api")
    assert not safe
    assert is_ssrf is True
    assert "Private" in reason

    safe, reason, is_ssrf = check_url_ssrf_safety("http://192.168.1.50:8080/")
    assert not safe
    assert is_ssrf is True
    assert "Private" in reason

    safe, reason, is_ssrf = check_url_ssrf_safety("http://[::1]/debug")
    assert not safe
    assert is_ssrf is True
    assert "Loopback" in reason

    safe, reason, is_ssrf = check_url_ssrf_safety("ftp://example.com/file")
    assert not safe
    assert is_ssrf is False
    assert "Prohibited URL scheme" in reason


def test_ssrf_blocks_domain_resolving_to_localhost():
    # Mock getaddrinfo resolving evil.internal to 127.0.0.1
    fake_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 80))]
    with patch("socket.getaddrinfo", return_value=fake_addrinfo):
        safe, reason, is_ssrf = check_url_ssrf_safety("http://evil.internal/secret")
        assert not safe
        assert is_ssrf is True
        assert "Loopback" in reason


def test_redirect_tracer_ssrf_prevention():
    analyzer = RedirectAnalyzer()

    # Should immediately halt without making any network request
    with patch("requests.get") as mock_get:
        res = analyzer.trace_redirects("http://169.254.169.254/meta-data")
        assert res.is_ssrf_blocked is True
        assert "Metadata" in (res.blocked_reason or "")
        mock_get.assert_not_called()


def test_redirect_tracer_follows_valid_hops():
    analyzer = RedirectAnalyzer(max_redirects=3)

    hop1_resp = MagicMock()
    hop1_resp.status_code = 302
    hop1_resp.headers = {"Location": "https://service.clean.com/landing"}
    hop1_resp.raw.read.return_value = b""

    hop2_resp = MagicMock()
    hop2_resp.status_code = 200
    hop2_resp.raw.read.return_value = b"<html>Landing</html>"

    # Pre-flight DNS check passes for global IP
    fake_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 443))]

    def mock_get(url, **kwargs):
        if "bit.ly" in url:
            return hop1_resp
        return hop2_resp

    with patch("socket.getaddrinfo", return_value=fake_addrinfo), patch("requests.get", side_effect=mock_get):
        res = analyzer.trace_redirects("https://bit.ly/testlink")
        assert res.is_ssrf_blocked is False
        assert res.hop_count == 1
        assert len(res.redirect_chain) == 2
        assert res.final_url == "https://service.clean.com/landing"
        assert res.is_disguised_domain is True


def test_url_reputation_virustotal_mocked():
    service = URLReputationService(virustotal_key="fake-key")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 5,
                    "suspicious": 1,
                    "harmless": 10,
                    "undetected": 50,
                },
                "categories": {"Forcepoint": "phishing"}
            }
        }
    }

    with patch("requests.get", return_value=mock_resp):
        res = service.lookup("http://phishingsite.xyz/login.php")
        assert res.provenance == ProvenanceType.VERIFIED
        assert res.is_malicious is True
        assert res.threat_score >= 70
        assert res.engine_detections == 5
