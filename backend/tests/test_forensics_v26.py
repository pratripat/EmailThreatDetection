"""
V2.6 Forensic Hardening Test Suite
Covers:
1. Received-Header Trust Adversarial Scenarios:
   - private -> public
   - public -> private
   - multiple public IPs (bottom-most public selected)
   - attacker-injected fake public Received header (candidate selection vs attribution UNVERIFIED)
   - malformed Received headers
   - no global IP (all private/local/documentation)
   - IPv4 + IPv6 mixed chain
   - multicast / documentation + public
   - multiple Received headers with conflicting candidates
2. Authentication Trust Model Hardening:
   - forged Authentication-Results with SPF/DKIM/DMARC pass (still UNVERIFIED)
   - forged auth header claiming DKIM pass with no DKIM-Signature header
   - DKIM-Signature exists but d= does not align with From domain (unaligned third-party)
   - authserv-id mismatch with receiving boundary MTA
   - multiple Authentication-Results headers (boundary vs interior)
   - completely missing Authentication-Results header
3. Arbitrary-Depth Private/Unlisted Suffix Fallback:
   - a.corp.internal vs corp.internal (SUBDOMAIN_RELATION)
   - a.b.corp.internal vs corp.internal (SUBDOMAIN_RELATION)
   - a.b.c.corp.internal vs corp.internal (SUBDOMAIN_RELATION)
   - a.b.corp.internal vs x.y.corp.internal (SAME_PRIVATE_SUFFIX)
   - a.b.c.corp.internal vs x.corp.internal (SAME_PRIVATE_SUFFIX)
   - attacker.internal vs victim.internal (UNRELATED)
   - mail.attacker.local vs smtp.victim.local (UNRELATED)
4. Comprehensive DomainRelation Enum Coverage:
   - EXACT_MATCH
   - SAME_REGISTRABLE_DOMAIN
   - SUBDOMAIN_RELATION
   - SAME_PRIVATE_SUFFIX
   - UNRELATED
   - UNKNOWN (None, empty, double dots, spaces)
5. Brand Impersonation Hardening (8 distinct scenarios):
   - A. Brand belongs to sender domain (0 penalty)
   - B. Incidental brand phrase (0 penalty)
   - C. Recognized ESP + clean auth (weak mismatch, 5 penalty)
   - D. Recognized ESP + failing auth (weak mismatch + fail, 25 penalty)
   - E. Unrelated attacker domain + clean auth (strong mismatch, 25 penalty)
   - F. Unrelated attacker domain + failing auth (critical spoofing, 40 penalty)
   - G. Unicode/Homoglyph brand spoofing
   - H. Brand in display name with misleading @ character
6. Forensic Uncertainty & Boundary Representation:
   - selected_origin_ip as candidate, origin_attribution as UNVERIFIED
   - receiving_boundary tracked from boundary MTA
   - print_report displays candidate and unverified status clearly
"""

import io
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

try:
    from backend.app.analyzers.header_forensics import (
        analyze_eml,
        compute_risk_score,
        detect_anomalies,
        domain_relationship,
        DomainRelation,
        evaluate_brand_impersonation,
        extract_ip_candidates,
        parse_auth_context,
        parse_received_header,
        print_report,
        select_origin_ip,
        RelayHop,
        ForensicReport,
    )
    from backend.app.analyzers.origin_analysis import OriginAnalyzer
except ImportError:
    from app.analyzers.header_forensics import (
        analyze_eml,
        compute_risk_score,
        detect_anomalies,
        domain_relationship,
        DomainRelation,
        evaluate_brand_impersonation,
        extract_ip_candidates,
        parse_auth_context,
        parse_received_header,
        print_report,
        select_origin_ip,
        RelayHop,
        ForensicReport,
    )
    from app.analyzers.origin_analysis import OriginAnalyzer

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


class DummyMsg(dict):
    """Mock email.message.EmailMessage for deterministic unit tests."""
    def get_all(self, k, default=None):
        v = self.get(k)
        if v is None:
            return default or []
        if isinstance(v, list):
            return v
        return [v]


class TestV26ReceivedHeaderTrust(unittest.TestCase):
    """Adversarial testing of Received-header origin selection and attribution trust."""

    def test_01_private_to_public(self):
        # Bottom hop is private, top hop is public
        headers = [
            'Received: from mail.gateway.com (gateway.com [93.184.216.34]) by mx.boundary.com with ESMTP',
            'Received: from internal.lan (node1 [10.0.0.15]) by mail.gateway.com with SMTP',
        ]
        hops = [parse_received_header(h) for h in headers]
        selected, reason, candidates = select_origin_ip(hops)
        self.assertEqual(selected, '93.184.216.34')
        self.assertEqual(len(candidates), 2)
        self.assertEqual(candidates[0]['ip'], '10.0.0.15')
        self.assertEqual(candidates[0]['classification'], 'private')
        self.assertEqual(candidates[1]['ip'], '93.184.216.34')
        self.assertEqual(candidates[1]['classification'], 'global')

    def test_02_public_to_private(self):
        # Bottom hop is public, top hop is internal private infrastructure
        headers = [
            'Received: from internal.core (core.lan [192.168.1.1]) by mailbox.local with LMTP',
            'Received: from edge.wan (edge.wan [93.184.216.34]) by internal.core with ESMTP',
        ]
        hops = [parse_received_header(h) for h in headers]
        selected, reason, candidates = select_origin_ip(hops)
        self.assertEqual(selected, '93.184.216.34')
        self.assertEqual(len(candidates), 2)

    def test_03_multiple_public_ips_bottom_most_selected(self):
        # Chain has multiple public IPs: bottom-most is client ingress, middle is upstream relay
        headers = [
            'Received: from relay2.wan.com [151.101.65.140] by mx.google.com with ESMTP',
            'Received: from relay1.wan.com [93.184.216.34] by relay2.wan.com with ESMTP',
            'Received: from lan.local [10.200.1.5] by relay1.wan.com with SMTP',
        ]
        hops = [parse_received_header(h) for h in headers]
        selected, reason, candidates = select_origin_ip(hops)
        # Should pick bottom-most public IP (relay1: 93.184.216.34), skipping private lan
        self.assertEqual(selected, '93.184.216.34')
        self.assertEqual(len(candidates), 3)

    def test_04_attacker_injected_fake_public_received_header(self):
        # Attacker injects a fake bottom Received header claiming 1.1.1.1 was the origin
        headers = [
            'Received: from real-edge.com (real-edge.com [93.184.216.34]) by mx.target.com with ESMTP',
            'Received: from fake-client ([1.1.1.1]) by real-edge.com with ESMTP',
        ]
        hops = [parse_received_header(h) for h in headers]
        selected, reason, candidates = select_origin_ip(hops)
        # 1.1.1.1 is selected as candidate based on routing rules
        self.assertEqual(selected, '1.1.1.1')
        # But provenance cannot be verified offline:
        report = ForensicReport(
            subject="Test", from_addr="a@b.com", return_path="a@b.com",
            message_id="<123>", relay_chain=hops, selected_origin_ip=selected,
            origin_selection_reason=reason, observed_candidates=candidates,
            origin_attribution="UNVERIFIED",
            origin_attribution_reason="Offline .eml analysis cannot establish which Received headers were inserted by trusted infrastructure vs fabricated by the sender."
        )
        self.assertEqual(report.origin_attribution, "UNVERIFIED")
        self.assertIn("cannot establish which Received headers were inserted", report.origin_attribution_reason)

    def test_05_malformed_received_headers(self):
        # Corrupted or malformed syntax in Received headers
        malformed_headers = [
            'Received: from [corrupted-ip] by mx.target.com',
            'Received: from by with id ;;;;;;',
            'Received: totally invalid random string without from or by',
            'Received: from real.com [93.184.216.34] by mx.target.com',
        ]
        hops = [parse_received_header(h) for h in malformed_headers]
        selected, reason, candidates = select_origin_ip(hops)
        # Should not throw exception, and should pick the valid public IP
        self.assertEqual(selected, '93.184.216.34')
        self.assertEqual(len(candidates), 1)

    def test_06_no_global_ip(self):
        # Entire chain consists only of private / local / loopback IPs
        headers = [
            'Received: from mta1.local [10.0.0.1] by mta2.local',
            'Received: from client.local [192.168.1.100] by mta1.local',
            'Received: from localhost [127.0.0.1] by client.local',
        ]
        hops = [parse_received_header(h) for h in headers]
        selected, reason, candidates = select_origin_ip(hops)
        self.assertIsNone(selected)
        self.assertIn("No publicly routable IP found", reason)
        self.assertEqual(len(candidates), 3)

    def test_07_ipv4_and_ipv6_mixed_chain(self):
        # Chain containing both IPv4 and IPv6 addresses
        headers = [
            'Received: from mx.google.com (mail.relay.com [2607:f8b0:4005:805::200e]) by mx.target.com',
            'Received: from sender.node [93.184.216.34] by mail.relay.com',
            'Received: from internal.lan [10.0.0.1] by sender.node',
        ]
        hops = [parse_received_header(h) for h in headers]
        selected, reason, candidates = select_origin_ip(hops)
        # Bottom-most global candidate is 93.184.216.34
        self.assertEqual(selected, '93.184.216.34')
        self.assertEqual(len(candidates), 3)

    def test_08_multicast_and_documentation_plus_public(self):
        # Multicast and documentation test ranges must be skipped
        headers = [
            'Received: from edge.wan.com [93.184.216.34] by mx.target.com',
            'Received: from doc.test [203.0.113.44] by edge.wan.com',
            'Received: from multi.cast [224.0.0.251] by doc.test',
        ]
        hops = [parse_received_header(h) for h in headers]
        selected, reason, candidates = select_origin_ip(hops)
        self.assertEqual(selected, '93.184.216.34')
        # All 3 observed, but only 93.184.216.34 is global
        self.assertEqual(len(candidates), 3)
        classifications = [c['classification'] for c in candidates]
        self.assertIn('multicast', classifications)
        self.assertIn('private', classifications)  # RFC 5737 classified as non-global/private
        self.assertIn('global', classifications)

    def test_09_multiple_candidates_in_single_header(self):
        # A single header containing both internal and external IP brackets
        header = 'Received: from client.gateway (lan [10.0.0.1] wan [93.184.216.34]) by mx.target.com'
        hop = parse_received_header(header)
        selected, reason, candidates = select_origin_ip([hop])
        self.assertEqual(selected, '93.184.216.34')
        self.assertEqual(len(candidates), 2)

    def test_10_special_unspecified_ips_rejected(self):
        # 0.0.0.0, 255.255.255.255, and :: must never be extracted as candidates
        header = 'Received: from bad.node [0.0.0.0] by mx.target.com [255.255.255.255]'
        hop = parse_received_header(header)
        selected, reason, candidates = select_origin_ip([hop])
        self.assertIsNone(selected)
        self.assertEqual(len(candidates), 0)

    def test_11_receiving_hop_not_selected_as_origin(self):
        # Google transit receiving hop (Received: by ...) must not be selected as origin over sender hop
        headers = [
            'Received: by mail-yx1-xb12e.google.com with SMTP id xyz (2607:f8b0:4864:20::b12e) for <user@gmail.com>',
            'Received: from mail.company.com (mail.company.com [93.184.216.34]) by mx.google.com with ESMTPS id abc',
        ]
        hops = [parse_received_header(h) for h in headers]
        selected, reason, candidates = select_origin_ip(hops)
        self.assertEqual(selected, '93.184.216.34')



class TestV26AuthenticationTrustModel(unittest.TestCase):
    """Hardened testing of authentication trust, multi-header handling, and DKIM alignment."""

    def test_01_forged_auth_results_with_all_pass_is_still_unverified(self):
        msg = DummyMsg({
            'Authentication-Results': 'mx.google.com; spf=pass smtp.mailfrom=victim.com; dkim=pass; dmarc=pass',
            'DKIM-Signature': 'v=1; a=rsa-sha256; d=victim.com; s=k1; b=fake;',
            'From': 'Victim <ceo@victim.com>',
        })
        hop = parse_received_header('Received: by mx.google.com with SMTP id xyz')
        ctx = parse_auth_context(msg, [hop])
        self.assertEqual(ctx['trust_status'], 'UNVERIFIED')
        self.assertEqual(ctx['verification'], 'UNVERIFIED')
        self.assertEqual(ctx['mechanisms']['spf'], 'pass')
        self.assertEqual(ctx['mechanisms']['dkim'], 'pass')
        self.assertEqual(ctx['mechanisms']['dmarc'], 'pass')

    def test_02_dkim_pass_claimed_without_dkim_signature_flagged(self):
        msg = DummyMsg({
            'Authentication-Results': 'mx.google.com; spf=pass; dkim=pass; dmarc=pass',
            'From': 'CEO <ceo@victim.com>',
            # No DKIM-Signature header
        })
        hop = parse_received_header('Received: by mx.google.com with SMTP id xyz')
        ctx = parse_auth_context(msg, [hop])
        self.assertEqual(ctx['trust_status'], 'UNVERIFIED')
        self.assertTrue(any('contradictory claim' in n for n in ctx['notes']))

    def test_03_unaligned_dkim_signature(self):
        msg = DummyMsg({
            'Authentication-Results': 'mx.google.com; spf=pass; dkim=pass; dmarc=pass',
            'DKIM-Signature': 'v=1; a=rsa-sha256; d=attacker-controlled.com; s=k1; b=fake;',
            'From': 'Executive <exec@bank.com>',
        })
        hop = parse_received_header('Received: by mx.google.com with SMTP id xyz')
        ctx = parse_auth_context(msg, [hop], from_domain='bank.com')
        self.assertEqual(ctx['trust_status'], 'UNVERIFIED')
        self.assertTrue(any('do not align with From domain (bank.com)' in n for n in ctx['notes']))

    def test_04_authserv_id_mismatch_with_boundary_mta(self):
        msg = DummyMsg({
            'Authentication-Results': 'mx.google.com; spf=pass; dkim=pass',
            'From': 'Support <support@example.com>',
        })
        # Boundary MTA is mail.evil-relay.com, not mx.google.com
        hop = parse_received_header('Received: by mail.evil-relay.com with SMTP id 123')
        ctx = parse_auth_context(msg, [hop])
        self.assertEqual(ctx['trust_status'], 'UNVERIFIED')
        self.assertTrue(any('does not match top receiving MTA' in n for n in ctx['notes']))

    def test_05_multiple_authentication_results_headers(self):
        # Multiple Authentication-Results headers (boundary vs interior)
        msg = DummyMsg({
            'Authentication-Results': [
                'mx.google.com; spf=fail; dkim=none',
                'internal-auth.upstream.com; spf=pass; dkim=pass',
            ],
            'From': 'Security <alert@example.com>',
        })
        hop = parse_received_header('Received: by mx.google.com with SMTP id abc')
        ctx = parse_auth_context(msg, [hop])
        # Only boundary header should be parsed
        self.assertEqual(ctx['mechanisms']['spf'], 'fail')
        self.assertEqual(ctx['mechanisms']['dkim'], 'none')
        self.assertTrue(any('Multiple (2) Authentication-Results headers detected' in n for n in ctx['notes']))

    def test_06_completely_missing_authentication_results(self):
        msg = DummyMsg({
            'From': 'User <user@example.com>',
        })
        hop = parse_received_header('Received: by mx.example.com with SMTP id 123')
        ctx = parse_auth_context(msg, [hop])
        self.assertEqual(ctx['trust_status'], 'MISSING')
        self.assertEqual(ctx['verification'], 'UNVERIFIED')
        self.assertIsNone(ctx['mechanisms']['spf'])
        self.assertIsNone(ctx['mechanisms']['dkim'])
        self.assertIsNone(ctx['mechanisms']['dmarc'])


class TestV26UnlistedPrivateTLD(unittest.TestCase):
    """Testing arbitrary-depth private and unlisted TLD resolution."""

    def test_arbitrary_depth_subdomains_unlisted(self):
        cases = [
            ('a.corp.internal', 'corp.internal', DomainRelation.SUBDOMAIN_RELATION),
            ('a.b.corp.internal', 'corp.internal', DomainRelation.SUBDOMAIN_RELATION),
            ('a.b.c.corp.internal', 'corp.internal', DomainRelation.SUBDOMAIN_RELATION),
            ('corp.internal', 'a.b.c.corp.internal', DomainRelation.SUBDOMAIN_RELATION),
            ('node.dc1.prod.company.local', 'company.local', DomainRelation.SUBDOMAIN_RELATION),
        ]
        for d1, d2, expected in cases:
            self.assertEqual(domain_relationship(d1, d2), expected, f"Failed for {d1} vs {d2}")

    def test_arbitrary_depth_siblings_unlisted(self):
        cases = [
            ('a.b.corp.internal', 'x.y.corp.internal', DomainRelation.SAME_PRIVATE_SUFFIX),
            ('a.b.c.corp.internal', 'x.corp.internal', DomainRelation.SAME_PRIVATE_SUFFIX),
            ('api.prod.infra.local', 'auth.prod.infra.local', DomainRelation.SAME_PRIVATE_SUFFIX),
        ]
        for d1, d2, expected in cases:
            self.assertEqual(domain_relationship(d1, d2), expected, f"Failed for {d1} vs {d2}")

    def test_unrelated_unlisted_domains(self):
        cases = [
            ('attacker.internal', 'victim.internal', DomainRelation.UNRELATED),
            ('a.attacker.internal', 'b.victim.internal', DomainRelation.UNRELATED),
            ('corp.internal', 'internal', DomainRelation.UNRELATED),
            ('mail.attacker.local', 'smtp.victim.local', DomainRelation.UNRELATED),
        ]
        for d1, d2, expected in cases:
            self.assertEqual(domain_relationship(d1, d2), expected, f"Failed for {d1} vs {d2}")


class TestV26DomainRelationEnumCoverage(unittest.TestCase):
    """Test all DomainRelation enum values and edge case inputs."""

    def test_all_enum_values_exercised(self):
        # EXACT_MATCH
        self.assertEqual(domain_relationship('example.com', 'example.com'), DomainRelation.EXACT_MATCH)
        self.assertEqual(domain_relationship('MAIL.EXAMPLE.COM', 'mail.example.com'), DomainRelation.EXACT_MATCH)
        self.assertEqual(
            domain_relationship('почта.яндекс.рф', 'xn--80a1acny.xn--d1acpjx3f.xn--p1ai'),
            DomainRelation.EXACT_MATCH
        )

        # SAME_REGISTRABLE_DOMAIN
        self.assertEqual(domain_relationship('mail.example.com', 'relay.example.com'), DomainRelation.SAME_REGISTRABLE_DOMAIN)
        self.assertEqual(domain_relationship('a.b.example.co.uk', 'c.d.example.co.uk'), DomainRelation.SAME_REGISTRABLE_DOMAIN)

        # SUBDOMAIN_RELATION
        self.assertEqual(domain_relationship('mail.example.com', 'example.com'), DomainRelation.SUBDOMAIN_RELATION)
        self.assertEqual(domain_relationship('example.com', 'mail.example.com'), DomainRelation.SUBDOMAIN_RELATION)

        # SAME_PRIVATE_SUFFIX
        self.assertEqual(domain_relationship('mail.corp.internal', 'smtp.corp.internal'), DomainRelation.SAME_PRIVATE_SUFFIX)

        # UNRELATED
        self.assertEqual(domain_relationship('attacker.com', 'victim.org'), DomainRelation.UNRELATED)
        self.assertEqual(domain_relationship('google.com', 'microsoft.com'), DomainRelation.UNRELATED)

        # UNKNOWN (Edge cases & malformed inputs)
        self.assertEqual(domain_relationship('', 'example.com'), DomainRelation.UNKNOWN)
        self.assertEqual(domain_relationship('example.com', ''), DomainRelation.UNKNOWN)
        self.assertEqual(domain_relationship(None, 'example.com'), DomainRelation.UNKNOWN)
        self.assertEqual(domain_relationship('example.com', None), DomainRelation.UNKNOWN)
        self.assertEqual(domain_relationship('invalid..domain', 'example.com'), DomainRelation.UNKNOWN)
        self.assertEqual(domain_relationship('invalid domain', 'example.com'), DomainRelation.UNKNOWN)


class TestV26BrandImpersonationHardening(unittest.TestCase):
    """Test all 8 brand impersonation scenarios."""

    def test_scenario_a_brand_belongs_to_domain(self):
        # Brand in display name, sender domain belongs to brand -> 0 penalty
        anom, cat, w = evaluate_brand_impersonation(
            'PayPal Service Updates', 'paypal.com',
            {'spf': 'pass', 'dkim': 'pass', 'dmarc': 'pass'}
        )
        self.assertIsNone(anom)
        self.assertEqual(cat, 'no meaningful brand mismatch (brand belongs to sender domain)')
        self.assertEqual(w, 0)

        # Subdomain also valid
        anom2, cat2, w2 = evaluate_brand_impersonation(
            'PayPal Support Team', 'service.paypal.com',
            {'spf': 'pass', 'dkim': 'pass', 'dmarc': 'pass'}
        )
        self.assertIsNone(anom2)
        self.assertEqual(w2, 0)

    def test_scenario_b_incidental_brand_word(self):
        # Display name contains brand word incidentally -> 0 penalty
        anom, cat, w = evaluate_brand_impersonation(
            'River Bank Restoration Initiative', 'river-project.org',
            {'spf': 'pass', 'dkim': 'pass', 'dmarc': 'pass'}
        )
        self.assertIsNone(anom)
        self.assertEqual(cat, 'no meaningful brand mismatch')
        self.assertEqual(w, 0)

    def test_scenario_c_legitimate_esp_with_clean_auth(self):
        # Known ESP + all auth pass -> weak mismatch (5 penalty)
        anom, cat, w = evaluate_brand_impersonation(
            'Google Workspace Notifications', 'sendgrid.net',
            {'spf': 'pass', 'dkim': 'pass', 'dmarc': 'pass'}
        )
        self.assertIn('weak brand mismatch', cat)
        self.assertEqual(w, 5)

    def test_scenario_d_legitimate_esp_with_failing_auth(self):
        # Known ESP + failing auth -> weak mismatch + failure (25 penalty)
        anom, cat, w = evaluate_brand_impersonation(
            'Google Workspace Notifications', 'sendgrid.net',
            {'spf': 'fail', 'dkim': 'pass', 'dmarc': 'pass'}
        )
        self.assertEqual(cat, 'weak mismatch + authentication failure')
        self.assertEqual(w, 25)

    def test_scenario_e_attacker_domain_with_clean_auth(self):
        # Unrelated domain + clean auth (attacker domain with valid SPF/DKIM) -> strong brand mismatch (25 penalty)
        anom, cat, w = evaluate_brand_impersonation(
            'Microsoft Security Alert', 'attacker-hosted-mailer.com',
            {'spf': 'pass', 'dkim': 'pass', 'dmarc': 'pass'}
        )
        self.assertEqual(cat, 'strong brand mismatch')
        self.assertEqual(w, 25)
        self.assertIn('strong brand mismatch', anom)

    def test_scenario_f_attacker_domain_with_failing_auth(self):
        # Unrelated domain + failing auth -> critical display-name spoofing (40 penalty)
        anom, cat, w = evaluate_brand_impersonation(
            'PayPal Security Team', 'freehostingnow.net',
            {'spf': 'fail', 'dkim': 'none', 'dmarc': 'fail'}
        )
        self.assertEqual(cat, 'strong mismatch + authentication failure')
        self.assertEqual(w, 40)
        self.assertIn('critical display-name spoofing indicator', anom)

    def test_scenario_g_unicode_homoglyph_brand_impersonation(self):
        # Display name uses Cyrillic homoglyphs: 'Pаypаl' with Cyrillic 'а' (\u0430)
        cyrillic_paypal = "P\u0430yp\u0430l Verification Team"
        anom, cat, w = evaluate_brand_impersonation(
            cyrillic_paypal, 'evil-attacker.ru',
            {'spf': 'fail', 'dkim': 'fail', 'dmarc': 'fail'}
        )
        self.assertEqual(cat, 'strong mismatch + authentication failure')
        self.assertEqual(w, 40)
        self.assertIn("Display name impersonates 'paypal'", anom)

    def test_scenario_h_brand_in_display_name_with_at_trick(self):
        # Header: From: "PayPal <service@paypal.com>" <spammer@evil.org>
        # detect_anomalies extracts display name and raw email
        msg = DummyMsg({
            'From': '"PayPal <service@paypal.com>" <spammer@evil.org>',
            'Return-Path': '<bounce@evil.org>',
            'Authentication-Results': 'mx.google.com; spf=fail; dkim=none; dmarc=fail',
        })
        hop = parse_received_header('Received: from evil.org [93.184.216.34] by mx.google.com')
        anomalies, domain_rel, brand_cat = detect_anomalies(msg, [hop], {'spf': 'fail', 'dkim': 'none', 'dmarc': 'fail'})
        self.assertEqual(brand_cat, 'strong mismatch + authentication failure')
        self.assertTrue(any('critical display-name spoofing indicator' in a for a in anomalies))


class TestV26ForensicUncertaintyAndReport(unittest.TestCase):
    """Verify uncertainty distinction, boundary tracking, and report formatting."""

    def test_origin_candidate_and_attribution_unverified(self):
        # Test that analyze_eml generates candidate and UNVERIFIED attribution
        report = analyze_eml(_sample_path('sample_clean.eml'))
        self.assertEqual(report.origin_attribution, 'UNVERIFIED')
        self.assertIn('cannot establish which Received headers were inserted', report.origin_attribution_reason)
        self.assertEqual(report.receiving_boundary, 'mx.google.com')
        self.assertEqual(report.auth_trust, 'UNVERIFIED')

    def test_print_report_terminology(self):
        report = analyze_eml(_sample_path('sample_clean.eml'))
        out = io.StringIO()
        with patch('sys.stdout', out):
            print_report(report)
        text = out.getvalue()
        self.assertIn('Selected origin candidate:  103.21.244.15', text)
        self.assertIn('Origin attribution:         UNVERIFIED', text)
        self.assertIn('Receiving boundary:         mx.google.com', text)
        self.assertIn('SPF:   PASS — claimed by Authentication-Results (unverified)', text)


if __name__ == '__main__':
    unittest.main()
