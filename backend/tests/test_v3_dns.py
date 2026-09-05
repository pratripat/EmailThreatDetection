from unittest.mock import patch, MagicMock
import dns.resolver
from backend.app.intelligence.dns_intelligence import DNSIntelligenceService
from backend.app.intelligence.models import ProvenanceType


def test_dns_resolution_mocked():
    service = DNSIntelligenceService(enabled=True)

    def mock_resolve(qname, rtype):
        qname_str = str(qname).rstrip(".")
        if rtype == "MX":
            m1 = MagicMock()
            m1.exchange = "mail.example.com."
            return [m1]
        elif rtype == "A":
            m1 = MagicMock()
            m1.__str__.return_value = "93.184.216.34"
            return [m1]
        elif rtype == "NS":
            m1 = MagicMock()
            m1.target = "ns1.example.com."
            return [m1]
        elif rtype == "TXT":
            m1 = MagicMock()
            if "_dmarc" in qname_str:
                m1.strings = (b"v=DMARC1; p=reject;",)
            else:
                m1.strings = (b"v=spf1 include:_spf.example.com ~all",)
            return [m1]
        raise dns.resolver.NoAnswer()

    with patch.object(service.resolver, "resolve", side_effect=mock_resolve):
        res = service.resolve_domain("example.com")
        assert res.provenance == ProvenanceType.VERIFIED
        assert "mail.example.com" in res.mx_records
        assert "93.184.216.34" in res.a_records
        assert "ns1.example.com" in res.ns_records
        assert res.spf_record == "v=spf1 include:_spf.example.com ~all"
        assert res.dmarc_record == "v=DMARC1; p=reject;"


def test_dnsbl_skips_private_ips():
    service = DNSIntelligenceService(enabled=True, dnsbl_enabled=True)
    with patch.object(service.resolver, "resolve") as mock_resolve:
        listed, matches = service.check_dnsbl("192.168.1.100")
        assert listed is False
        assert matches == []
        mock_resolve.assert_not_called()

        listed, matches = service.check_dnsbl("127.0.0.1")
        assert listed is False
        mock_resolve.assert_not_called()


def test_dnsbl_mocked_listed_ip():
    service = DNSIntelligenceService(enabled=True, dnsbl_enabled=True, dnsbl_zones=["zen.spamhaus.org"])

    def mock_resolve(qname, rtype):
        if str(qname).startswith("4.3.2.1.zen.spamhaus.org"):
            m = MagicMock()
            return [m]
        raise dns.resolver.NXDOMAIN()

    with patch.object(service.resolver, "resolve", side_effect=mock_resolve):
        listed, matches = service.check_dnsbl("1.2.3.4")
        assert listed is True
        assert "zen.spamhaus.org" in matches


def test_dns_disabled_offline():
    service = DNSIntelligenceService(enabled=False)
    with patch.object(service.resolver, "resolve") as mock_resolve:
        res = service.resolve_domain("example.com")
        mock_resolve.assert_not_called()
        assert res.provenance == ProvenanceType.NOT_CHECKED
