"""
Header Anomaly Detection Core
Detects domain mismatches, brand impersonation, authentication failures, and relay chain anomalies.
"""

import re
import email.utils
import unicodedata
from typing import Tuple, List, Optional, Dict, Any

from .domain_utils import (
    domain_relationship,
    DomainRelation,
    registrable_domain,
    normalize_domain,
    load_brand_list,
    HOMOGLYPH_MAP
)

KNOWN_ESP_DOMAINS = {
    'sending-service.com', 'sendgrid.net', 'sendgrid.com', 'mailchimp.com',
    'mcsv.net', 'amazonses.com', 'createsend.com', 'hubspot.com',
    'zendesk.com', 'salesforce.com', 'mailgun.org', 'mailgun.net',
    'sparkpostmail.com', 'postmarkapp.com'
}

INCIDENTAL_PHRASES = {
    'bank': ['river bank', 'food bank', 'blood bank', 'data bank', 'snow bank', 'seed bank', 'west bank']
}


def evaluate_brand_impersonation(display_name: str, from_domain_raw: str, auth_results: dict) -> Tuple[Optional[str], str, int]:
    """Evaluate display-name brand impersonation with confidence-aware tiering."""
    if not display_name or not from_domain_raw:
        return None, "no meaningful brand mismatch", 0

    display_name_clean = unicodedata.normalize('NFKC', display_name).lower()
    display_name_dehomoglyph = display_name_clean.translate(HOMOGLYPH_MAP)
    from_domain_norm = normalize_domain(from_domain_raw)
    from_domain_lower = from_domain_norm.lower()

    common_brands = load_brand_list()

    detected_brand = None
    for brand in common_brands:
        pattern = r'\b' + re.escape(brand) + r'\b'
        if re.search(pattern, display_name_clean) or re.search(pattern, display_name_dehomoglyph):
            if brand in INCIDENTAL_PHRASES:
                if any(phrase in display_name_clean or phrase in display_name_dehomoglyph for phrase in INCIDENTAL_PHRASES[brand]):
                    continue
            detected_brand = brand
            break

    if not detected_brand:
        return None, "no meaningful brand mismatch", 0

    brand_domain = f"{detected_brand}.com"
    rel_with_brand = domain_relationship(from_domain_lower, brand_domain)
    if rel_with_brand in (DomainRelation.EXACT_MATCH, DomainRelation.SUBDOMAIN_RELATION, DomainRelation.SAME_REGISTRABLE_DOMAIN):
        return None, "no meaningful brand mismatch (brand belongs to sender domain)", 0

    reg_d = registrable_domain(from_domain_lower)
    domain_root = reg_d.split('.')[0] if '.' in reg_d else reg_d
    if domain_root == detected_brand:
        return None, "no meaningful brand mismatch (brand belongs to sender domain)", 0

    is_esp = (
        from_domain_lower in KNOWN_ESP_DOMAINS or
        any(from_domain_lower.endswith('.' + esp) for esp in KNOWN_ESP_DOMAINS) or
        'sending-service' in from_domain_lower or
        'mailservice' in from_domain_lower
    )

    all_auth_passed = (
        auth_results.get('spf') == 'pass' and
        auth_results.get('dkim') == 'pass' and
        auth_results.get('dmarc') == 'pass'
    )

    if is_esp:
        if all_auth_passed:
            anomaly = (
                f"Display name references brand '{detected_brand}' via authorized delivery "
                f"service '{from_domain_lower}' — weak brand mismatch (legitimate ESP delivery)"
            )
            return anomaly, "weak brand mismatch", 5
        else:
            anomaly = (
                f"Display name references brand '{detected_brand}' via delivery domain "
                f"'{from_domain_lower}' with failing authentication — possible spoofed ESP"
            )
            return anomaly, "weak mismatch + authentication failure", 25
    else:
        if all_auth_passed:
            anomaly = (
                f"Display name claims brand '{detected_brand}' from unrelated domain "
                f"'{from_domain_lower}' (claimed auth passes for sender's own domain, but does "
                f"not authorize brand representation) — strong brand mismatch"
            )
            return anomaly, "strong brand mismatch", 25
        else:
            anomaly = (
                f"Display name impersonates '{detected_brand}' but sending domain is "
                f"'{from_domain_lower}' with failing authentication — critical display-name spoofing indicator"
            )
            return anomaly, "strong mismatch + authentication failure", 40


def detect_anomalies(msg, relay_chain: list, auth_results: dict) -> Tuple[List[str], Optional[str], Optional[str]]:
    """Rule-based anomaly detection core."""
    anomalies = []

    from_addr = msg.get('From', '')
    return_path = msg.get('Return-Path', '')

    display_name, from_email = email.utils.parseaddr(from_addr)
    _, return_email = email.utils.parseaddr(return_path or '')

    from_domain_raw = from_email.split('@')[-1].lower() if '@' in from_email else None
    return_domain_raw = return_email.split('@')[-1].lower() if '@' in return_email else None

    domain_rel_str = None
    if from_domain_raw and return_domain_raw:
        rel = domain_relationship(from_domain_raw, return_domain_raw)
        domain_rel_str = rel.value

        if rel == DomainRelation.UNRELATED:
            anomalies.append(
                f"MISMATCH: From domain ({from_domain_raw}) != "
                f"Return-Path domain ({return_domain_raw}) "
                f"— classic spoofing/BEC indicator"
            )
    elif from_addr or return_path:
        anomalies.append(
            "MALFORMED SENDER ADDRESS: could not extract a valid email address from "
            "From/Return-Path — headers may be corrupted or deliberately obfuscated"
        )

    spf = auth_results.get('spf')
    if spf == 'fail':
        anomalies.append("SPF check: FAIL (hard failure — domain owner explicitly disavows this sender)")
    elif spf == 'softfail':
        anomalies.append("SPF check: SOFTFAIL (domain owner does not fully authorize sender, but policy is not strict)")
    elif spf == 'neutral':
        anomalies.append("SPF check: NEUTRAL (domain owner explicitly states neutrality or no policy for sender)")
    elif spf not in ('pass', None):
        anomalies.append(f"SPF check: {spf} (expected 'pass')")
    elif spf is None:
        anomalies.append("SPF check: MISSING (expected 'pass')")

    if auth_results.get('dkim') not in ('pass',):
        anomalies.append(f"DKIM check: {auth_results.get('dkim') or 'MISSING'} (expected 'pass')")
    if auth_results.get('dmarc') not in ('pass',):
        anomalies.append(f"DMARC check: {auth_results.get('dmarc') or 'MISSING'} (expected 'pass')")

    if len(relay_chain) == 0:
        anomalies.append("No Received headers found — highly unusual, possible header stripping")
    elif len(relay_chain) > 8:
        anomalies.append(f"Unusually long relay chain ({len(relay_chain)} hops) — possible relay abuse")

    brand_anom, brand_category, _ = evaluate_brand_impersonation(display_name, from_domain_raw or '', auth_results)
    if brand_anom:
        anomalies.append(brand_anom)

    return anomalies, domain_rel_str, brand_category
