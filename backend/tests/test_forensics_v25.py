"""
V2.5 Forensic Correctness Test Suite
Verifies:
1. Received-header origin selection across 8 topological scenarios
2. Claimed vs verified authentication trust handling
3. Confidence-aware brand impersonation evaluation across 6 scenarios
4. Reusable domain_relationship abstraction
5. Structured forensic investigation output
6. Missing intelligence data files robustness (OriginDataError)
7. End-to-end clean and spoofed sample regression
"""

import os
import sys
import tempfile
import unittest

from pathlib import Path

# Add backend and root directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

try:
    from backend.app.analyzers.header_forensics import (
        analyze_eml,
        detect_anomalies,
        compute_risk_score,
        domain_relationship,
        DomainRelation,
        parse_received_header,
        select_origin_ip,
        parse_auth_context,
        evaluate_brand_impersonation,
        print_report
    )
    from backend.app.analyzers.origin_analysis import OriginAnalyzer, OriginDataError, classify_ip_type
except ImportError:
    from app.analyzers.header_forensics import (
        analyze_eml,
        detect_anomalies,
        compute_risk_score,
        domain_relationship,
        DomainRelation,
        parse_received_header,
        select_origin_ip,
        parse_auth_context,
        evaluate_brand_impersonation,
        print_report
    )
    from app.analyzers.origin_analysis import OriginAnalyzer, OriginDataError, classify_ip_type

def _sample_path(filename):
    for candidate in [
        filename,
        os.path.join(os.path.dirname(__file__), 'fixtures', filename),
        os.path.join(os.path.dirname(__file__), '..', filename),
        os.path.join(os.path.dirname(__file__), '..', '..', filename),
    ]:
        if os.path.exists(candidate):
            return candidate
    return filename


class TestV25ForensicCorrectness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.analyzer = OriginAnalyzer()

    # =========================================================================
    # 1. Received-Header Origin Selection Tests
    # =========================================================================
    def test_origin_selection_scenarios(self):
        scenarios = {
            'private -> private -> public': {
                'headers': [
                    'Received: from mail.target.com (mx.edge.com [45.135.232.19]) by mx.google.com with ESMTP',
                    'Received: from internal.relay.com (internal.relay.com [192.168.1.1]) by mx.edge.com with ESMTP',
                    'Received: from client.local (client.local [10.0.0.1]) by internal.relay.com with SMTP',
                ],
                'expected_selected': '45.135.232.19',
                'expected_candidates_count': 3
            },
            'public -> private': {
                'headers': [
                    'Received: from internal.mx (internal.mx [10.0.0.1]) by corporate.core.local',
                    'Received: from sender.public.com (sender.public.com [45.135.232.19]) by internal.mx with ESMTP',
                ],
                'expected_selected': '45.135.232.19',
                'expected_candidates_count': 2
            },
            'private -> public -> public': {
                'headers': [
                    'Received: from mx2.google.com [172.217.1.1] by mx.google.com',
                    'Received: from edge.sender.com [45.135.232.19] by mx2.google.com',
                    'Received: from lan.sender.local [10.0.0.50] by edge.sender.com',
                ],
                'expected_selected': '45.135.232.19',
                'expected_candidates_count': 3
            },
            'IPv6 private -> IPv6 public': {
                'headers': [
                    'Received: from mx.google.com (mail.relay.com [2607:f8b0:4005:805::200e]) by mx.target.com',
                    'Received: from [fe80::1] by mail.relay.com',
                ],
                'expected_selected': '2607:f8b0:4005:805::200e',
                'expected_candidates_count': 2
            },
            'only private IPs': {
                'headers': [
                    'Received: from relay2 [192.168.1.2] by internal.server',
                    'Received: from relay1 [10.0.0.1] by relay2',
                ],
                'expected_selected': None,
                'expected_candidates_count': 2
            },
            'multicast + public': {
                'headers': [
                    'Received: from edge.com [45.135.232.19] by mx.target.com',
                    'Received: from [224.0.0.1] by edge.com',
                ],
                'expected_selected': '45.135.232.19',
                'expected_candidates_count': 2
            },
            'documentation IP + public': {
                'headers': [
                    'Received: from edge.com [45.135.232.19] by mx.target.com',
                    'Received: from [203.0.113.44] by edge.com',
                ],
                'expected_selected': '45.135.232.19',
                'expected_candidates_count': 2
            },
            'malformed + public': {
                'headers': [
                    'Received: from edge.com [45.135.232.19] by mx.target.com',
                    'Received: from not-an-ip-string by edge.com',
                ],
                'expected_selected': '45.135.232.19',
                'expected_candidates_count': 1
            },
        }

        for name, data in scenarios.items():
            hops = [parse_received_header(h) for h in data['headers']]
            selected_ip, reason, candidates = select_origin_ip(hops)
            self.assertEqual(selected_ip, data['expected_selected'], f"Failed scenario: {name}")
            self.assertEqual(len(candidates), data['expected_candidates_count'], f"Candidate mismatch in {name}")
            self.assertTrue(len(reason) > 0)

    # =========================================================================
    # 2. Claimed vs Trusted Authentication Tests
    # =========================================================================
    def test_authentication_trust_representation(self):
        class DummyMsg(dict):
            def get_all(self, k, default=None):
                v = self.get(k)
                return [v] if v else (default or [])

        # 1. Clean claimed auth without live verification -> UNVERIFIED
        msg_clean = DummyMsg({
            'Authentication-Results': 'mx.google.com; spf=pass smtp.mailfrom=college.edu; dkim=pass header.i=@college.edu; dmarc=pass',
            'DKIM-Signature': 'v=1; a=rsa-sha256; c=relaxed/relaxed; d=college.edu; s=2026; h=from:to:subject;'
        })
        hop_clean = parse_received_header('Received: by mx.google.com with SMTP id ab1cd2ef')
        ctx_clean = parse_auth_context(msg_clean, [hop_clean])
        self.assertEqual(ctx_clean['trust_status'], 'UNVERIFIED')
        self.assertEqual(ctx_clean['mechanisms']['spf'], 'pass')
        self.assertEqual(ctx_clean['mechanisms']['dkim'], 'pass')
        self.assertEqual(ctx_clean['dkim_signatures'], ['college.edu'])

        # 2. Injected / contradictory DKIM claim without signature header
        msg_no_sig = DummyMsg({
            'Authentication-Results': 'mx.google.com; spf=pass; dkim=pass; dmarc=pass'
        })
        ctx_no_sig = parse_auth_context(msg_no_sig, [hop_clean])
        self.assertEqual(ctx_no_sig['trust_status'], 'UNVERIFIED')
        self.assertTrue(any('contradictory claim' in note for note in ctx_no_sig['notes']))

        # 3. Missing Authentication-Results header
        msg_missing = DummyMsg({})
        ctx_missing = parse_auth_context(msg_missing, [hop_clean])
        self.assertEqual(ctx_missing['trust_status'], 'MISSING')
        self.assertIsNone(ctx_missing['mechanisms']['spf'])

    # =========================================================================
    # 3. Confidence-Aware Brand Impersonation Tests
    # =========================================================================
    def test_brand_impersonation_scenarios(self):
        # 1. Legitimate ESP + clean auth
        anom, cat, w = evaluate_brand_impersonation(
            'Google Cloud Platform Team', 'sending-service.com',
            {'spf': 'pass', 'dkim': 'pass', 'dmarc': 'pass'}
        )
        self.assertEqual(cat, 'weak brand mismatch')
        self.assertEqual(w, 5)

        # 2. Legitimate ESP + failing auth
        anom, cat, w = evaluate_brand_impersonation(
            'Google Cloud Platform Team', 'sending-service.com',
            {'spf': 'fail', 'dkim': 'pass', 'dmarc': 'pass'}
        )
        self.assertEqual(cat, 'weak mismatch + authentication failure')
        self.assertEqual(w, 25)

        # 3. Obvious brand impersonation + clean claimed auth (attacker domain)
        anom, cat, w = evaluate_brand_impersonation(
            'Google Security Team', 'attacker-example.com',
            {'spf': 'pass', 'dkim': 'pass', 'dmarc': 'pass'}
        )
        self.assertEqual(cat, 'strong brand mismatch')
        self.assertEqual(w, 25)
        self.assertIsNotNone(anom)
        self.assertIn('strong brand mismatch', anom)

        # 4. Obvious brand impersonation + failing auth
        anom, cat, w = evaluate_brand_impersonation(
            'PayPal Security Team', 'freehostingnow.net',
            {'spf': 'fail', 'dkim': 'none', 'dmarc': 'fail'}
        )
        self.assertEqual(cat, 'strong mismatch + authentication failure')
        self.assertEqual(w, 40)
        self.assertIn('critical display-name spoofing indicator', anom)

        # 5. Brand actually belonging to sender domain
        anom, cat, w = evaluate_brand_impersonation(
            'Google Workspace', 'google.com',
            {'spf': 'pass', 'dkim': 'pass', 'dmarc': 'pass'}
        )
        self.assertEqual(cat, 'no meaningful brand mismatch (brand belongs to sender domain)')
        self.assertEqual(w, 0)
        self.assertIsNone(anom)

        # 6. Display name containing brand word incidentally
        anom, cat, w = evaluate_brand_impersonation(
            'River Bank Restoration Project', 'riverproject.org',
            {'spf': 'pass', 'dkim': 'pass', 'dmarc': 'pass'}
        )
        self.assertEqual(cat, 'no meaningful brand mismatch')
        self.assertEqual(w, 0)
        self.assertIsNone(anom)

    # =========================================================================
    # 4. Reusable Domain Relationship Tests
    # =========================================================================
    def test_domain_relationship(self):
        cases = [
            ('college.edu', 'college.edu', DomainRelation.EXACT_MATCH),
            ('mail.college.edu', 'college.edu', DomainRelation.SUBDOMAIN_RELATION),
            ('mail.college.edu', 'relay.college.edu', DomainRelation.SAME_REGISTRABLE_DOMAIN),
            ('mail.corp.internal', 'corp.internal', DomainRelation.SUBDOMAIN_RELATION),
            ('mail.corp.internal', 'smtp.corp.internal', DomainRelation.SAME_PRIVATE_SUFFIX),
            ('почта.яндекс.рф', 'xn--80a1acny.xn--d1acpjx3f.xn--p1ai', DomainRelation.EXACT_MATCH),
            ('attacker.com', 'victim.com', DomainRelation.UNRELATED),
            ('', 'victim.com', DomainRelation.UNKNOWN),
            ('invalid..domain', 'valid.com', DomainRelation.UNKNOWN),
        ]
        for d1, d2, expected in cases:
            rel = domain_relationship(d1, d2)
            self.assertEqual(rel, expected, f"Failed for {d1} vs {d2}")

    # =========================================================================
    # 5. Missing Data File Robustness Test
    # =========================================================================
    def test_missing_data_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Pointing OriginAnalyzer to empty tempdir must raise OriginDataError, not FileNotFoundError
            with self.assertRaises(OriginDataError) as ctx:
                OriginAnalyzer(data_dir=tmpdir)
            err_msg = str(ctx.exception)
            self.assertIn('Required data file not found', err_msg)
            self.assertIn('curl -o', err_msg)

    # =========================================================================
    # 6. End-to-End Baseline Samples Regression Tests
    # =========================================================================
    def test_sample_clean_regression(self):
        report = analyze_eml(_sample_path('sample_clean.eml'), analyzer=self.analyzer)
        self.assertEqual(report.risk_score, 0, "sample_clean.eml should score 0/100")
        self.assertEqual(len(report.anomalies), 0, "sample_clean.eml should have 0 anomalies")
        self.assertEqual(report.selected_origin_ip, '103.21.244.15')
        self.assertEqual(report.domain_relation, 'EXACT_MATCH')
        self.assertEqual(report.auth_trust, 'UNVERIFIED')

    def test_sample_spoofed_regression(self):
        report = analyze_eml(_sample_path('sample_spoofed.eml'), analyzer=self.analyzer)
        self.assertEqual(report.risk_score, 85, "sample_spoofed.eml should score 85/100")
        self.assertEqual(len(report.anomalies), 4, "sample_spoofed.eml should have 4 anomalies")
        self.assertEqual(report.selected_origin_ip, '45.135.232.19')
        self.assertEqual(report.auth_trust, 'UNVERIFIED')
        self.assertIn('critical display-name spoofing indicator', ' '.join(report.anomalies))


if __name__ == '__main__':
    unittest.main()
