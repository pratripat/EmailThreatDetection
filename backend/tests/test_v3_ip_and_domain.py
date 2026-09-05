from unittest.mock import patch, MagicMock
from backend.app.intelligence.ip_reputation import IPReputationService, AbuseIPDBProvider, VirusTotalIPProvider
from backend.app.intelligence.domain_intelligence import DomainIntelligenceService, to_punycode
from backend.app.intelligence.models import ProvenanceType


def test_punycode_normalization():
    assert to_punycode("münchen.de") == "xn--mnchen-3ya.de"
    assert to_punycode("example.com") == "example.com"
    assert to_punycode("GOOGLE.COM") == "google.com"


def test_ip_intel_strictly_skips_private_ips():
    service = IPReputationService(abuseipdb_key="fake-key", virustotal_key="fake-key")

    # None of these should make any network requests
    with patch("requests.get") as mock_get:
        # Loopback
        res_loopback = service.lookup("127.0.0.1")
        assert res_loopback.is_non_routable is True
        assert res_loopback.provenance == ProvenanceType.OBSERVED
        assert res_loopback.reputation == "UNKNOWN"

        # RFC1918 Private
        res_private = service.lookup("10.1.2.3")
        assert res_private.is_non_routable is True
        assert res_private.provenance == ProvenanceType.OBSERVED

        # IPv6 Loopback
        res_ipv6 = service.lookup("::1")
        assert res_ipv6.is_non_routable is True

        # Link-local / Cloud Metadata IP
        res_linklocal = service.lookup("169.254.169.254")
        assert res_linklocal.is_non_routable is True

        # Documentation RFC 5737
        res_doc = service.lookup("203.0.113.1")
        assert res_doc.is_non_routable is True

        # Verify requests.get was NEVER called for non-routable IPs
        mock_get.assert_not_called()


def test_ip_intel_mocked_external_provider():
    service = IPReputationService(abuseipdb_key="test-abuse-key", virustotal_key="test-vt-key")

    mock_abuse_resp = MagicMock()
    mock_abuse_resp.status_code = 200
    mock_abuse_resp.json.return_value = {
        "data": {
            "abuseConfidenceScore": 85,
            "isWhitelisted": False,
            "totalReports": 42,
            "countryCode": "RU",
            "countryName": "Russia",
            "isp": "BadHost Inc",
            "domain": "badhost.net"
        }
    }

    mock_vt_resp = MagicMock()
    mock_vt_resp.status_code = 200
    mock_vt_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 8, "suspicious": 2, "harmless": 20, "undetected": 40},
                "asn": 12345,
                "as_owner": "BadHost Autonomous System",
                "country": "RU"
            }
        }
    }

    def side_effect(url, **kwargs):
        if "abuseipdb" in url:
            return mock_abuse_resp
        return mock_vt_resp

    with patch("requests.get", side_effect=side_effect):
        res = service.lookup("198.51.100.0")  # Note: if 198.51.100.0 is doc IP it will skip, let's use global routable IP
        # 185.220.101.5 is a public IP
        res = service.lookup("185.220.101.5")
        assert res.is_non_routable is False
        assert res.abuse_score == 85
        assert res.reputation == "MALICIOUS"
        assert res.abuse_category == "HIGH RISK"
        assert res.provenance == ProvenanceType.VERIFIED
        assert res.country_code == "RU"
        assert res.isp == "BadHost Autonomous System"
        assert res.virus_total_ratio == "8/70"


def test_domain_intelligence_rdap_mocked():
    service = DomainIntelligenceService(enabled=True)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    # Registration 10 days ago -> newly registered
    mock_resp.json.return_value = {
        "events": [
            {"eventAction": "registration", "eventDate": "2026-08-25T00:00:00Z"}
        ],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Namecheap Inc."]]]
            }
        ]
    }

    with patch("requests.get", return_value=mock_resp):
        res = service.lookup("suspicious-fresh-domain.xyz")
        assert res.provenance == ProvenanceType.VERIFIED
        assert res.registrar == "Namecheap Inc."
        assert res.registered_age_days >= 0
        assert res.is_newly_registered is True


def test_domain_intelligence_offline_disabled():
    service = DomainIntelligenceService(enabled=False)
    with patch("requests.get") as mock_get:
        res = service.lookup("example.com")
        mock_get.assert_not_called()
        assert res.registered_age_days == -1
        assert res.provenance == ProvenanceType.NOT_CHECKED
