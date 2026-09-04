"""
InvestigationData JSON Contract Validation Test Suite
Validates schema compliance across 11 distinct email topologies and edge cases:
1. Clean .eml
2. Spoofed .eml
3. Malformed .eml
4. Empty / minimal .eml
5. Email with IPv4 Received headers
6. Email with IPv6 Received headers
7. Email with embedded URLs
8. Email with multipart HTML
9. Email with attachments
10. Missing authentication headers
11. Multiple Received headers (relay chain)
"""

import json
import math
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from backend.app.services.investigation_service import InvestigationService
from backend.app.models.investigation import InvestigationData


def _fixture_path(filename: str) -> str:
    candidates = [
        filename,
        os.path.join(os.path.dirname(__file__), 'fixtures', filename),
        os.path.join(os.path.dirname(__file__), '..', filename),
        os.path.join(os.path.dirname(__file__), '..', '..', filename),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return filename


class TestInvestigationContractValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.service = InvestigationService()

    def _assert_contract(self, investigation: InvestigationData):
        """Validate that the returned InvestigationData strictly complies with all JSON schema rules."""
        # 1. Pydantic validation (guarantees schema types)
        self.assertIsInstance(investigation, InvestigationData)
        
        # 2. JSON Serialization without NaN/Infinity
        data_dict = investigation.model_dump(by_alias=True)
        json_str = json.dumps(data_dict)
        deserialized = json.loads(json_str)

        # 3. Required top-level fields
        required_keys = [
            'id', 'subject', 'from', 'to', 'receivedDate', 'threatScore',
            'threatLevel', 'threatType', 'confidence', 'authStatus',
            'breakdown', 'suspiciousReasons', 'headerHops', 'authentication',
            'urls', 'contentAi', 'iocs', 'attackGraph'
        ]
        for k in required_keys:
            self.assertIn(k, deserialized, f"Missing required top-level key '{k}'")

        # Top-level string fields
        self.assertIsInstance(deserialized['subject'], str)
        self.assertIsInstance(deserialized['from'], str)
        self.assertIsInstance(deserialized['to'], str)
        self.assertIsInstance(deserialized['receivedDate'], str)

        # 4. Numeric value bounds & no NaN/Inf
        self.assertTrue(0 <= deserialized['threatScore'] <= 100)
        self.assertFalse(math.isnan(deserialized['threatScore']))
        self.assertTrue(0.0 <= deserialized['confidence'] <= 1.0)
        self.assertFalse(math.isnan(deserialized['confidence']))

        # 5. Enum validation: threatLevel NEVER outputs MEDIUM
        self.assertIn(deserialized['threatLevel'], ["CLEAN", "LOW", "SUSPICIOUS", "HIGH", "CRITICAL"])
        self.assertNotEqual(deserialized['threatLevel'], "MEDIUM", "threatLevel must never be MEDIUM")
        self.assertIn(deserialized['authStatus'], ["PASSED", "FAILED", "PARTIAL"])

        # 6. Nested Breakdown validation (never scoreBreakdown)
        self.assertNotIn('scoreBreakdown', deserialized)
        breakdown = deserialized['breakdown']
        for bk in ['headerAnomalies', 'authentication', 'urlRisk', 'contentNlp', 'senderReputation']:
            self.assertIn(bk, breakdown)
            self.assertTrue(0 <= breakdown[bk] <= 100)

        # 7. Authentication nested structure
        auth = deserialized['authentication']
        self.assertIn(auth['spf'], ["PASSED", "FAILED", "SOFTFAIL", "NONE"])
        self.assertIn(auth['dkim'], ["PASSED", "FAILED", "NONE"])
        self.assertIn(auth['dmarc'], ["PASSED", "FAILED", "NONE"])
        self.assertIsInstance(auth['fromDomain'], str)
        self.assertIsInstance(auth['returnPathDomain'], str)
        self.assertIsInstance(auth['alignmentMatched'], bool)
        self.assertIsInstance(auth['notes'], list)

        # 8. HeaderHops nested structure
        hops = deserialized['headerHops']
        self.assertIsInstance(hops, list)
        for h in hops:
            self.assertIn('hopNumber', h)
            self.assertIn('ip', h)
            self.assertIn('hostname', h)
            self.assertIn('country', h)
            self.assertIn('asn', h)
            self.assertIn('isp', h)
            self.assertIn('reputation', h)
            self.assertIn(h['reputation'], ["MALICIOUS", "SUSPICIOUS", "CLEAN", "UNKNOWN"])
            self.assertIn('firstSeen', h)
            self.assertIn('threatFeeds', h)
            tf = h['threatFeeds']
            self.assertIn('abuseIpDb', tf)
            self.assertIn('virusTotal', tf)
            self.assertIn('spamhausListed', tf)
            self.assertIsInstance(tf['spamhausListed'], bool)

        # 9. URLs nested structure
        urls = deserialized['urls']
        self.assertIsInstance(urls, list)
        for u in urls:
            self.assertIn('url', u)
            self.assertIn('domain', u)
            self.assertIn('registeredAgeDays', u)
            self.assertIsInstance(u['registeredAgeDays'], int)
            self.assertIn('reputation', u)
            self.assertIn(u['reputation'], ["MALICIOUS", "SUSPICIOUS", "SAFE", "UNKNOWN"])
            self.assertIn('threatScore', u)
            self.assertIn('flags', u)

        # 10. ContentAi nested structure
        cai = deserialized['contentAi']
        self.assertIn(cai['classification'], ["PHISHING", "SPOOFING", "BEC_FRAUD", "BENIGN", "MALWARE_DROP"])
        self.assertIsInstance(cai['confidence'], float)
        self.assertIsInstance(cai['intents'], list)
        self.assertIsInstance(cai['suspiciousPhrases'], list)
        for sp in cai['suspiciousPhrases']:
            self.assertIn('phrase', sp)
            self.assertIn('signalType', sp)
            self.assertIn(sp['signalType'], ["Urgency signal", "Credential request", "Financial coercion", "Security impersonation"])
        self.assertIsInstance(cai['featureContributions'], list)

        # 11. IOCs nested lists
        iocs = deserialized['iocs']
        for ik in ['ipAddresses', 'domains', 'urls', 'emailAddresses', 'hashes']:
            self.assertIn(ik, iocs)
            self.assertIsInstance(iocs[ik], list)

        # 12. AttackGraph structure (exact frontend node types, statuses, and from/to edge keys)
        ag = deserialized['attackGraph']
        self.assertIsInstance(ag['nodes'], list)
        self.assertIsInstance(ag['edges'], list)
        for n in ag['nodes']:
            self.assertIn('id', n)
            self.assertIn('label', n)
            self.assertIn('sublabel', n)
            self.assertIn('type', n)
            self.assertIn(n['type'], ["email", "domain", "ip", "page", "action"])
            self.assertIn('status', n)
            self.assertIn(n['status'], ["critical", "warning", "clean", "neutral"])
        for e in ag['edges']:
            self.assertIn('from', e)
            self.assertIn('to', e)
            self.assertNotIn('source', e)
            self.assertNotIn('target', e)
            self.assertNotIn('relation', e)

    def test_case_01_clean_eml(self):
        with open(_fixture_path('sample_clean.eml'), 'rb') as f:
            res = self.service.analyze_email(f.read())
        self._assert_contract(res)
        self.assertEqual(res.threatScore, 0)
        self.assertEqual(res.threatLevel, 'CLEAN')

    def test_case_02_spoofed_eml(self):
        with open(_fixture_path('sample_spoofed.eml'), 'rb') as f:
            res = self.service.analyze_email(f.read())
        self._assert_contract(res)
        self.assertEqual(res.threatScore, 85)
        self.assertEqual(res.threatLevel, 'HIGH')

    def test_case_03_malformed_eml(self):
        raw = b"Invalid Header: \n\nCorrupted content with no valid headers or delimiters."
        res = self.service.analyze_email(raw)
        self._assert_contract(res)

    def test_case_04_empty_minimal_eml(self):
        raw = b"Subject: Empty\n\n"
        res = self.service.analyze_email(raw)
        self._assert_contract(res)

    def test_case_05_ipv4_received_headers(self):
        raw = (
            b"From: sender@domain.com\n"
            b"To: recipient@target.com\n"
            b"Subject: IPv4 Test\n"
            b"Received: from edge.wan.com [93.184.216.34] by mx.target.com\n"
            b"Received: from internal.lan [10.0.0.5] by edge.wan.com\n\n"
            b"Testing IPv4 relay hops."
        )
        res = self.service.analyze_email(raw)
        self._assert_contract(res)
        self.assertTrue(len(res.headerHops) >= 2)

    def test_case_06_ipv6_received_headers(self):
        raw = (
            b"From: sender@domain.com\n"
            b"To: recipient@target.com\n"
            b"Subject: IPv6 Test\n"
            b"Received: from relay.wan (relay [2607:f8b0:4005:805::200e]) by mx.target.com\n\n"
            b"Testing IPv6 relay hop."
        )
        res = self.service.analyze_email(raw)
        self._assert_contract(res)
        self.assertTrue(any("2607:f8b0:4005:805::200e" in h.ip for h in res.headerHops))

    def test_case_07_email_with_urls(self):
        raw = (
            b"From: bank@security-notice.com\n"
            b"To: user@target.com\n"
            b"Subject: Phishing URL Test\n"
            b"Authentication-Results: mx.target.com; spf=fail; dkim=none\n\n"
            b"Please visit http://paypal-security-update.account-verify.xyz/login immediately."
        )
        res = self.service.analyze_email(raw)
        self._assert_contract(res)
        self.assertTrue(len(res.urls) >= 1)
        self.assertEqual(res.urls[0].threatScore, 100)

    def test_case_08_multipart_html(self):
        raw = (
            b"MIME-Version: 1.0\n"
            b"Content-Type: multipart/alternative; boundary=\"boundary123\"\n"
            b"Subject: HTML Email\n"
            b"From: info@example.com\n"
            b"To: user@example.com\n\n"
            b"--boundary123\n"
            b"Content-Type: text/plain; charset=utf-8\n\n"
            b"Plain text content.\n"
            b"--boundary123\n"
            b"Content-Type: text/html; charset=utf-8\n\n"
            b"<html><body><a href=\"https://secure.example.com/portal\">Click Portal</a></body></html>\n"
            b"--boundary123--\n"
        )
        res = self.service.analyze_email(raw)
        self._assert_contract(res)
        self.assertTrue(any("https://secure.example.com/portal" in u.url for u in res.urls))

    def test_case_09_email_with_attachments(self):
        raw = (
            b"MIME-Version: 1.0\n"
            b"Content-Type: multipart/mixed; boundary=\"attboundary\"\n"
            b"Subject: Invoice Attached\n"
            b"From: accounting@vendor.com\n"
            b"To: finance@client.com\n\n"
            b"--attboundary\n"
            b"Content-Type: text/plain\n\n"
            b"Please find attached your invoice.\n"
            b"--attboundary\n"
            b"Content-Type: application/pdf; name=\"invoice_1001.pdf\"\n"
            b"Content-Disposition: attachment; filename=\"invoice_1001.pdf\"\n"
            b"Content-Transfer-Encoding: base64\n\n"
            b"JVBERi0xLjQKJcTl8uXrCg==\n"
            b"--attboundary--\n"
        )
        res = self.service.analyze_email(raw)
        self._assert_contract(res)
        self.assertTrue(len(res.iocs.hashes) >= 1)

    def test_case_10_missing_authentication_headers(self):
        raw = (
            b"From: unauthenticated@relay.net\n"
            b"To: user@target.com\n"
            b"Subject: Missing Auth\n"
            b"Received: from edge [93.184.216.34] by mx.target.com\n\n"
            b"No authentication results present."
        )
        res = self.service.analyze_email(raw)
        self._assert_contract(res)
        self.assertEqual(res.authentication.spf, "NONE")
        self.assertEqual(res.authentication.dkim, "NONE")
        self.assertEqual(res.authentication.dmarc, "NONE")
        self.assertEqual(res.authStatus, "PARTIAL")

    def test_case_11_multiple_received_headers(self):
        raw = (
            b"From: sender@domain.com\n"
            b"To: recipient@target.com\n"
            b"Subject: Multi-Hop Relay Test\n"
            b"Received: from hop3.mx [151.101.65.140] by final.mta\n"
            b"Received: from hop2.mta [93.184.216.34] by hop3.mx\n"
            b"Received: from hop1.client [10.1.1.5] by hop2.mta\n\n"
            b"Multi-hop test."
        )
        res = self.service.analyze_email(raw)
        self._assert_contract(res)
        self.assertEqual(len(res.headerHops), 3)

    def test_case_12_fixture_contract_validation(self):
        fixture_file = _fixture_path('sample_investigation_response.json')
        self.assertTrue(os.path.exists(fixture_file), f"Fixture file not found: {fixture_file}")
        with open(fixture_file, 'r', encoding='utf-8') as f:
            fixture_json = json.load(f)
        validated = InvestigationData.model_validate(fixture_json)
        self._assert_contract(validated)

    def test_case_13_task_10_explicit_contract_checks(self):
        with open(_fixture_path('sample_spoofed.eml'), 'rb') as f:
            res = self.service.analyze_email(f.read())
        dump = res.model_dump(by_alias=True)

        # 1. Exact required top-level keys
        for key in ['id', 'subject', 'from', 'to', 'receivedDate', 'threatScore',
                    'threatLevel', 'threatType', 'confidence', 'authStatus',
                    'breakdown', 'suspiciousReasons', 'headerHops', 'authentication',
                    'urls', 'contentAi', 'iocs', 'attackGraph']:
            self.assertIn(key, dump, f"Missing required key: {key}")

        # 2. No unexpected replacement names such as scoreBreakdown
        self.assertNotIn('scoreBreakdown', dump)
        self.assertNotIn('summaryFindings', dump)
        self.assertNotIn('emailMetadata', dump)

        # 3. threatLevel never outputs MEDIUM
        self.assertNotEqual(dump['threatLevel'], 'MEDIUM')
        self.assertIn(dump['threatLevel'], ['CRITICAL', 'HIGH', 'SUSPICIOUS', 'LOW', 'CLEAN'])

        # 4. breakdown has all five required fields
        self.assertIn('headerAnomalies', dump['breakdown'])
        self.assertIn('authentication', dump['breakdown'])
        self.assertIn('urlRisk', dump['breakdown'])
        self.assertIn('contentNlp', dump['breakdown'])
        self.assertIn('senderReputation', dump['breakdown'])

        # 5. authStatus exists and is valid
        self.assertIn(dump['authStatus'], ['PASSED', 'FAILED', 'PARTIAL'])

        # 6. confidence exists
        self.assertIsInstance(dump['confidence'], float)

        # 7. suspiciousReasons exists
        self.assertIsInstance(dump['suspiciousReasons'], list)

        # 8. subject, from, to, receivedDate exist as strings
        self.assertIsInstance(dump['subject'], str)
        self.assertIsInstance(dump['from'], str)
        self.assertIsInstance(dump['to'], str)
        self.assertIsInstance(dump['receivedDate'], str)

        # 9. Attack graph node types and statuses
        for node in dump['attackGraph']['nodes']:
            self.assertIn(node['type'], ['email', 'domain', 'ip', 'page', 'action'])
            self.assertIn(node['status'], ['critical', 'warning', 'clean', 'neutral'])
            self.assertIsInstance(node['sublabel'], str)
        for edge in dump['attackGraph']['edges']:
            self.assertIn('from', edge)
            self.assertIn('to', edge)


if __name__ == '__main__':
    unittest.main()
