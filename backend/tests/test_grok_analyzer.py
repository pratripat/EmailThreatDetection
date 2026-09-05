"""
Test Suite for Grok URL Analyzer & Grok AI Integration
Tests:
1. URL extraction from text, HTML, and EML structures.
2. Deterministic heuristic analysis & reputation mapping.
3. Grok AI classification (BENIGN, PHISHING, MALICIOUS, SUSPICIOUS) with mocked completions.
4. Graceful degradation when Grok API is disabled or throws an exception.
5. Pydantic model serialization & contract compatibility (AnalyzedUrl, GrokAnalysis, InvestigationData).
6. End-to-end integration via InvestigationService.
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch
from email.message import EmailMessage

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from backend.app.analyzers.grok_url_analyzer import GrokURLAnalyzer
from backend.app.models.investigation import AnalyzedUrl, GrokAnalysis, InvestigationData
from backend.app.services.investigation_service import InvestigationService


class TestGrokURLAnalyzer(unittest.TestCase):
    def setUp(self):
        # Initialized with disabled / dummy state for unit tests
        self.analyzer = GrokURLAnalyzer(api_key="")

    # --------------------------------------------------------------------------
    # 1. Extraction Tests
    # --------------------------------------------------------------------------
    def test_extract_urls_from_text(self):
        sample_text = (
            "Hello, please visit https://example.com/login and check "
            "http://test.org/path?a=1&b=2 for updates."
        )
        urls = self.analyzer.extract_urls(sample_text)
        self.assertEqual(len(urls), 2)
        self.assertIn("https://example.com/login", urls)
        self.assertIn("http://test.org/path?a=1&b=2", urls)

    def test_extract_urls_from_html(self):
        html = """
        <html>
            <body>
                <p>Click <a href="https://legitimate.org/docs">here</a> for docs.</p>
                <a href="http://phishing-site.xyz/verify">Sign in</a>
                <span>Also see https://plain-text-link.com/info</span>
            </body>
        </html>
        """
        urls = self.analyzer.extract_urls_from_html(html)
        self.assertEqual(len(urls), 3)
        self.assertIn("https://legitimate.org/docs", urls)
        self.assertIn("http://phishing-site.xyz/verify", urls)
        self.assertIn("https://plain-text-link.com/info", urls)

    def test_extract_urls_from_email_object(self):
        msg = EmailMessage()
        msg["From"] = "attacker@bad-domain.com"
        msg["To"] = "victim@company.com"
        msg["Subject"] = "Urgent Account Update"
        msg["Reply-To"] = "https://reply-tracking.com/r"
        msg.set_content("Please click https://inner-body.com/reset to proceed.")
        msg.add_alternative("<p>HTML <a href='https://html-link.com/login'>here</a></p>", subtype="html")

        urls = self.analyzer.extract_urls_from_email(msg)
        self.assertIn("https://reply-tracking.com/r", urls)
        self.assertIn("https://inner-body.com/reset", urls)
        self.assertIn("https://html-link.com/login", urls)

    # --------------------------------------------------------------------------
    # 2. Deterministic Fallback Tests
    # --------------------------------------------------------------------------
    def test_deterministic_benign_url(self):
        res = self.analyzer.analyze_url("https://www.google.com/search?q=cybersecurity")
        self.assertEqual(res["reputation"], "SAFE")
        self.assertLessEqual(res["threatScore"], 30)
        self.assertIsNone(res["grok_analysis"])

        # Validate with Pydantic model
        validated = AnalyzedUrl(**res)
        self.assertEqual(validated.reputation, "SAFE")
        self.assertIsNone(validated.grok_analysis)

    def test_deterministic_phishing_indicators(self):
        # Raw IP, plain HTTP, security keywords
        res = self.analyzer.analyze_url("http://192.168.1.1/admin/login.php")
        self.assertEqual(res["reputation"], "MALICIOUS")
        self.assertGreaterEqual(res["threatScore"], 60)
        self.assertTrue(any("IP address" in f for f in res["flags"]))
        self.assertIsNone(res["grok_analysis"])

    def test_deterministic_brand_impersonation(self):
        res = self.analyzer.analyze_url("http://paypal.verify-account.top/signin")
        self.assertEqual(res["reputation"], "MALICIOUS")
        self.assertGreaterEqual(res["threatScore"], 60)
        self.assertTrue(any("brand" in f.lower() for f in res["flags"]))

    # --------------------------------------------------------------------------
    # 3. Grok AI Integration Tests (Mocked)
    # --------------------------------------------------------------------------
    def test_grok_ai_phishing_classification(self):
        analyzer = GrokURLAnalyzer(api_key="xai-test-key-12345")
        self.assertTrue(analyzer.enabled)

        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = (
            "VERDICT: PHISHING\n"
            "CONFIDENCE: 95%\n"
            "REASON: Domain impersonates banking portal with spoofed subdomain and unencrypted HTTP.\n"
            "FLAGS: Brand Impersonation, Credential Harvesting, Suspicious Subdomain"
        )
        mock_response.choices = [mock_choice]

        with patch.object(analyzer.client.chat.completions, "create", return_value=mock_response):
            res = analyzer.analyze_url("http://chase.online-verify.xyz/login")

            self.assertEqual(res["reputation"], "MALICIOUS")
            self.assertGreaterEqual(res["threatScore"], 80)
            self.assertIsNotNone(res["grok_analysis"])
            self.assertEqual(res["grok_analysis"]["verdict"], "PHISHING")
            self.assertEqual(res["grok_analysis"]["confidence"], 0.95)
            self.assertIn("banking portal", res["grok_analysis"]["reason"])

            # Verify Pydantic model serialization
            validated = AnalyzedUrl(**res)
            self.assertEqual(validated.grok_analysis.verdict, "PHISHING")
            self.assertEqual(validated.grok_analysis.confidence, 0.95)

    def test_grok_ai_benign_classification(self):
        analyzer = GrokURLAnalyzer(api_key="xai-test-key-12345")

        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = (
            "VERDICT: BENIGN\n"
            "CONFIDENCE: 0.98\n"
            "REASON: Legitimate Wikipedia article on computer security.\n"
            "FLAGS: None"
        )
        mock_response.choices = [mock_choice]

        with patch.object(analyzer.client.chat.completions, "create", return_value=mock_response):
            res = analyzer.analyze_url("https://en.wikipedia.org/wiki/Computer_security")

            self.assertEqual(res["reputation"], "SAFE")
            self.assertLessEqual(res["threatScore"], 20)
            self.assertIsNotNone(res["grok_analysis"])
            self.assertEqual(res["grok_analysis"]["verdict"], "BENIGN")
            self.assertEqual(res["grok_analysis"]["confidence"], 0.98)

            validated = AnalyzedUrl(**res)
            self.assertEqual(validated.grok_analysis.verdict, "BENIGN")

    def test_grok_ai_json_response_parsing(self):
        analyzer = GrokURLAnalyzer(api_key="xai-test-key-12345")

        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = """
        ```json
        {
            "verdict": "SUSPICIOUS",
            "confidence": 0.72,
            "reason": "Recently registered domain offering free prizes with multiple redirects.",
            "flags": ["New Domain", "Lure Content"]
        }
        ```
        """
        mock_response.choices = [mock_choice]

        with patch.object(analyzer.client.chat.completions, "create", return_value=mock_response):
            res = analyzer.analyze_url("http://free-rewards.win-today.click")

            self.assertEqual(res["reputation"], "SUSPICIOUS")
            self.assertIsNotNone(res["grok_analysis"])
            self.assertEqual(res["grok_analysis"]["verdict"], "SUSPICIOUS")
            self.assertEqual(res["grok_analysis"]["confidence"], 0.72)
            self.assertIn("free prizes", res["grok_analysis"]["reason"])

    def test_grok_ai_graceful_degradation_on_api_error(self):
        analyzer = GrokURLAnalyzer(api_key="xai-test-key-12345")

        # Simulate an API error (timeout or connection failure)
        with patch.object(analyzer.client.chat.completions, "create", side_effect=Exception("API connection timeout")):
            res = analyzer.analyze_url("http://paypal-security-update.xyz/login")

            # Must degrade gracefully to deterministic analysis
            self.assertIn(res["reputation"], ["MALICIOUS", "SUSPICIOUS"])
            self.assertGreater(res["threatScore"], 0)
            self.assertIsNone(res["grok_analysis"])

            validated = AnalyzedUrl(**res)
            self.assertIsNone(validated.grok_analysis)

    # --------------------------------------------------------------------------
    # 4. End-to-End InvestigationService Integration
    # --------------------------------------------------------------------------
    def test_investigation_service_e2e_with_grok(self):
        service = InvestigationService()
        
        eml_bytes = (
            b"From: security@paypal-alerts.net\r\n"
            b"To: user@example.com\r\n"
            b"Subject: Action Required: Account Suspension\r\n"
            b"Date: Sat, 5 Sep 2026 10:00:00 +0000\r\n"
            b"Content-Type: text/html\r\n\r\n"
            b"<html><body>Please verify your account: <a href='http://paypal-verify.evil-login.xyz/signin'>Verify Now</a></body></html>"
        )

        result: InvestigationData = service.analyze_email(eml_bytes)
        self.assertIsInstance(result, InvestigationData)
        self.assertEqual(len(result.urls), 1)

        analyzed_url = result.urls[0]
        self.assertEqual(analyzed_url.domain, "evil-login.xyz")
        self.assertEqual(analyzed_url.reputation, "MALICIOUS")
        self.assertGreaterEqual(analyzed_url.threatScore, 60)
        self.assertIn("evil-login.xyz", analyzed_url.url)

        # JSON serialization check
        dumped = result.model_dump(by_alias=True)
        self.assertIn("urls", dumped)
        self.assertEqual(len(dumped["urls"]), 1)
        self.assertIn("grok_analysis", dumped["urls"][0])


if __name__ == "__main__":
    unittest.main()
