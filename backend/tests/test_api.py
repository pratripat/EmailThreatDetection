"""
API Integration Test Suite
Tests FastAPI endpoints:
- GET /api/health
- POST /api/analyze-email (file upload, raw text, clean, spoofed, empty, malformed)
"""

import os
import sys
import unittest
from pathlib import Path
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from backend.app.main import app
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


class TestBackendApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_01_health_endpoint(self):
        response = self.client.get('/api/health')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data.get('status'), 'healthy')
        self.assertIn('service', data)
        self.assertIn('version', data)

    def test_02_analyze_clean_email_file(self):
        clean_path = _fixture_path('sample_clean.eml')
        with open(clean_path, 'rb') as f:
            response = self.client.post(
                '/api/analyze-email',
                files={'email': ('sample_clean.eml', f, 'message/rfc822')}
            )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        # Validate against Pydantic model
        validated = InvestigationData(**data)
        self.assertEqual(validated.threatScore, 0)
        self.assertEqual(validated.threatLevel, 'CLEAN')
        self.assertEqual(validated.threatType, 'BENIGN')
        self.assertEqual(validated.authStatus, 'PASSED')
        self.assertEqual(len(validated.suspiciousReasons), 0)
        self.assertEqual(validated.breakdown.headerAnomalies, 0)

    def test_03_analyze_spoofed_email_file(self):
        spoofed_path = _fixture_path('sample_spoofed.eml')
        with open(spoofed_path, 'rb') as f:
            response = self.client.post(
                '/api/analyze-email',
                files={'email': ('sample_spoofed.eml', f, 'message/rfc822')}
            )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        validated = InvestigationData(**data)
        self.assertEqual(validated.threatScore, 85)
        self.assertEqual(validated.threatLevel, 'HIGH')
        self.assertEqual(validated.threatType, 'PHISHING')
        self.assertEqual(validated.authStatus, 'FAILED')
        self.assertTrue(len(validated.suspiciousReasons) >= 4)
        self.assertEqual(validated.breakdown.headerAnomalies, 85)
        self.assertTrue(len(validated.headerHops) >= 2)
        self.assertTrue(len(validated.urls) >= 1)
        self.assertTrue(len(validated.attackGraph.nodes) >= 3)

    def test_04_analyze_raw_email_text(self):
        raw_eml = (
            "From: notifications@college.edu\n"
            "To: student@college.edu\n"
            "Subject: Campus Notice\n"
            "Date: Fri, 04 Sep 2026 12:00:00 +0000\n"
            "Received: by mx.google.com with SMTP id test123\n"
            "Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass\n\n"
            "Classes are held online today."
        )
        response = self.client.post(
            '/api/analyze-email',
            data={'raw_email_text': raw_eml}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        validated = InvestigationData(**data)
        self.assertEqual(validated.subject, 'Campus Notice')
        self.assertEqual(validated.authStatus, 'PASSED')

    def test_05_empty_input_returns_400(self):
        response = self.client.post('/api/analyze-email')
        self.assertEqual(response.status_code, 400)
        self.assertIn('No email content provided', response.json().get('detail', ''))

    def test_06_malformed_email_handled_gracefully(self):
        corrupted_bytes = b"This is totally non-email garbage text \x00\x01\x02 with no headers\n\nBody only"
        response = self.client.post(
            '/api/analyze-email',
            files={'email': ('corrupted.eml', corrupted_bytes, 'application/octet-stream')}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        validated = InvestigationData(**data)
        # Should not crash, returns fallback investigation structure
        self.assertIsNotNone(validated.id)
        self.assertIsNotNone(validated.threatLevel)


if __name__ == '__main__':
    unittest.main()
