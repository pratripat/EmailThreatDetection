"""
Email Header Forensics Module — SIH26106 prototype (V2.5 Forensic Correctness)
Parses raw .eml files and extracts forensic indicators:
- Relay path reconstruction & robust origin selection
- Dual-stack IPv4/IPv6 origin intelligence
- Reusable domain relationship analysis (PSL/IDNA aware)
- Claimed vs verified authentication representation
- Confidence-aware brand impersonation evaluation
- Evidence-gated anomaly scoring

Deterministic core — no LLM, no ML model. Pure header parsing & rule-based forensics.
"""

from enum import Enum
import email
import email.utils
from email import policy
from email.parser import BytesParser
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Optional
import unicodedata
import tldextract
import sys
from pathlib import Path

# Common homoglyph translation table for Cyrillic/Greek lookalikes in Latin text
HOMOGLYPH_MAP = str.maketrans({
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',
    'у': 'y', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'В': 'b',
    'А': 'a', 'Е': 'e', 'О': 'o', 'Р': 'p', 'С': 'c', 'Т': 't'
})

try:
    from .origin_analysis import OriginAnalyzer, OriginDataError, classify_ip_type
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent))
    from origin_analysis import OriginAnalyzer, OriginDataError, classify_ip_type

# Public Suffix List extractor (bundled offline snapshot)
_tld_extractor = tldextract.TLDExtract(suffix_list_urls=())


def _normalize_domain(domain: str) -> str:
    """Normalize domain to canonical lowercase ASCII/Punycode.
    V2 Fix Item 1: ensures Unicode (e.g. почта.яндекс.рф) and Punycode
    (xn--80a1acny.xn--d1acpjx3f.xn--p1ai) representations match cleanly."""
    if not domain:
        return ""
    domain = domain.strip().lower()
    if domain.endswith('.'):
        domain = domain[:-1]
    try:
        import idna
        return idna.encode(domain, uts46=True).decode('ascii')
    except Exception:
        try:
            return domain.encode('idna').decode('ascii')
        except Exception:
            return domain


def _registrable_domain(domain: str) -> str:
    """Reduce a domain to its registrable form: mail.college.edu -> college.edu.
    Returns the input unchanged (lowercased) if extraction fails or yields nothing
    useful, so callers always get a usable string."""
    if not domain:
        return domain
    norm = _normalize_domain(domain)
    result = _tld_extractor(norm)
    return result.top_domain_under_public_suffix or norm


class DomainRelation(str, Enum):
    EXACT_MATCH = "EXACT_MATCH"
    SAME_REGISTRABLE_DOMAIN = "SAME_REGISTRABLE_DOMAIN"
    SUBDOMAIN_RELATION = "SUBDOMAIN_RELATION"
    SAME_PRIVATE_SUFFIX = "SAME_PRIVATE_SUFFIX"
    UNRELATED = "UNRELATED"
    UNKNOWN = "UNKNOWN"


def domain_relationship(domain_a: str, domain_b: str) -> DomainRelation:
    """Analyze the forensic relationship between two domains.
    V2.6: Robust reusable domain abstraction supporting arbitrary-depth
    unlisted/private suffixes, PSL/tldextract, IDN/Punycode, and malformed inputs."""
    if not isinstance(domain_a, str) or not isinstance(domain_b, str):
        return DomainRelation.UNKNOWN
    if not domain_a.strip() or not domain_b.strip():
        return DomainRelation.UNKNOWN

    if '..' in domain_a or '..' in domain_b or ' ' in domain_a or ' ' in domain_b:
        return DomainRelation.UNKNOWN

    norm_a = _normalize_domain(domain_a)
    norm_b = _normalize_domain(domain_b)

    if not norm_a or not norm_b:
        return DomainRelation.UNKNOWN

    if norm_a == norm_b:
        return DomainRelation.EXACT_MATCH

    res_a = _tld_extractor(norm_a)
    res_b = _tld_extractor(norm_b)

    has_recognized_suffix = bool(res_a.suffix and res_b.suffix)

    if has_recognized_suffix:
        reg_a = res_a.top_domain_under_public_suffix or norm_a
        reg_b = res_b.top_domain_under_public_suffix or norm_b

        if reg_a == reg_b:
            if norm_a.endswith('.' + norm_b) or norm_b.endswith('.' + norm_a):
                return DomainRelation.SUBDOMAIN_RELATION
            else:
                return DomainRelation.SAME_REGISTRABLE_DOMAIN
        else:
            return DomainRelation.UNRELATED
    else:
        # Fallback for unlisted/private suffixes (.internal, .local, .corp)
        labels_a = norm_a.split('.')
        labels_b = norm_b.split('.')

        # Subdomain relation: one domain is a dot-prefixed suffix of the other (with >= 2 labels in parent)
        if len(labels_b) >= 2 and norm_a.endswith('.' + norm_b):
            return DomainRelation.SUBDOMAIN_RELATION
        if len(labels_a) >= 2 and norm_b.endswith('.' + norm_a):
            return DomainRelation.SUBDOMAIN_RELATION

        # Sibling / same private suffix relation: share at least 2 common suffix labels
        common_count = 0
        for la, lb in zip(reversed(labels_a), reversed(labels_b)):
            if la == lb:
                common_count += 1
            else:
                break
        if common_count >= 2:
            return DomainRelation.SAME_PRIVATE_SUFFIX

        return DomainRelation.UNRELATED


@dataclass
class RelayHop:
    raw: str
    from_host: Optional[str] = None
    by_host: Optional[str] = None
    with_protocol: Optional[str] = None
    timestamp: Optional[str] = None


@dataclass
class ForensicReport:
    subject: str
    from_addr: str
    return_path: Optional[str]
    message_id: Optional[str]
    relay_chain: list = field(default_factory=list)
    spf_result: Optional[str] = None
    dkim_result: Optional[str] = None
    dmarc_result: Optional[str] = None
    anomalies: list = field(default_factory=list)
    earliest_ip: Optional[str] = None
    origin_label: Optional[str] = None
    origin_explanation: Optional[str] = None
    risk_score: int = 0  # 0-100, higher = more suspicious

    # V2.5 / V2.6 additions for explainable forensic investigation
    selected_origin_ip: Optional[str] = None
    origin_selection_reason: Optional[str] = None
    observed_candidates: list = field(default_factory=list)
    domain_relation: Optional[str] = None
    auth_trust: str = "UNVERIFIED"
    auth_context: dict = field(default_factory=dict)
    brand_assessment: Optional[str] = None
    limitations: list = field(default_factory=list)
    origin_attribution: str = "UNVERIFIED"
    origin_attribution_reason: str = "Offline .eml analysis cannot establish which Received headers were inserted by trusted infrastructure vs fabricated by the sender."
    receiving_boundary: Optional[str] = None


IPV4_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


def parse_received_header(raw_header: str) -> RelayHop:
    """Extract from/by/with/timestamp from a single Received: header."""
    hop = RelayHop(raw=raw_header)

    from_match = re.search(r'from\s+(.*?)\s+(?:by|with|id|via|for|;|\r?\n|$)', raw_header, re.DOTALL | re.IGNORECASE)
    if from_match:
        hop.from_host = ' '.join(from_match.group(1).split())
    else:
        from_match_old = re.search(r'from\s+([^\s]+(?:\s+\([^)]+\))?)', raw_header, re.IGNORECASE)
        if from_match_old:
            hop.from_host = from_match_old.group(1)

    by_match = re.search(r'by\s+([^\s;]+)', raw_header, re.IGNORECASE)
    if by_match:
        hop.by_host = by_match.group(1)

    with_match = re.search(r'with\s+([^\s;]+)', raw_header, re.IGNORECASE)
    if with_match:
        hop.with_protocol = with_match.group(1)

    ts_match = re.search(r';\s*(.+)$', raw_header.strip(), re.DOTALL)
    if ts_match:
        hop.timestamp = ' '.join(ts_match.group(1).strip().split())

    return hop


def extract_ip_candidates(text: str) -> list:
    """Extract all valid IPv4 and IPv6 candidate addresses from text in priority order."""
    if not text:
        return []
    candidates = []

    # 1. Bracketed expressions: [192.0.2.1] or [2001:db8::1] or [IPv6:2001:db8::1]
    for b in re.findall(r'\[(?:IPv6:)?([^\]]+)\]', text, re.IGNORECASE):
        cleaned = b.split('%')[0].strip()
        try:
            candidates.append(str(ipaddress.ip_address(cleaned)))
        except ValueError:
            pass

    # 2. IPv6 prefix outside brackets: IPv6:2001:db8::1
    for b in re.findall(r'IPv6:([0-9a-fA-F:]+(?:%[a-zA-Z0-9_-]+)?)', text, re.IGNORECASE):
        cleaned = b.split('%')[0].strip()
        try:
            candidates.append(str(ipaddress.ip_address(cleaned)))
        except ValueError:
            pass

    # 3. Standard IPv4 addresses
    for m in IPV4_PATTERN.findall(text):
        try:
            candidates.append(str(ipaddress.IPv4Address(m)))
        except ValueError:
            pass

    # 4. Standalone IPv6 tokens with at least 2 colons
    for token in re.findall(r'\b[0-9a-fA-F:]{3,}\b', text):
        if token.count(':') >= 2:
            cleaned = token.split('%')[0].strip()
            try:
                ip_obj = ipaddress.ip_address(cleaned)
                if isinstance(ip_obj, ipaddress.IPv6Address):
                    candidates.append(str(ip_obj))
            except ValueError:
                pass

    # Deduplicate preserving order
    seen = set()
    result = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            result.append(c)
    return result


def extract_ip_from_hop(hop: RelayHop) -> Optional[str]:
    """Pull the first valid IPv4 or IPv6 address out of a relay hop."""
    if not hop:
        return None
    candidates = extract_ip_candidates(hop.from_host or '')
    if candidates:
        return candidates[0]
    raw_candidates = extract_ip_candidates(hop.raw or '')
    return raw_candidates[0] if raw_candidates else None


def select_origin_ip(relay_chain: list) -> tuple:
    """Select the first publicly routable/global origin IP candidate from the Received chain.
    V2.5 Item 1: Traverses from earliest hop (bottom) to latest hop (top), preserving
    all observed internal/private/multicast hops while correctly preferring the public ingress IP."""
    observed_candidates = []
    selected_ip = None
    selection_reason = ""

    # Chronological traversal: bottom (earliest) to top (latest)
    for hop in reversed(relay_chain):
        candidates = extract_ip_candidates(hop.from_host or '')
        if not candidates:
            candidates = extract_ip_candidates(hop.raw or '')

        for ip_str in candidates:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                ctype = classify_ip_type(ip_obj)
            except ValueError:
                ctype = "invalid"

            observed_candidates.append({
                "ip": ip_str,
                "classification": ctype,
                "from_host": hop.from_host
            })

            if selected_ip is None and ctype == "global":
                selected_ip = ip_str
                selection_reason = "First publicly routable/global candidate in the Received chain."

    if selected_ip is None:
        if observed_candidates:
            types = ", ".join(f"{c['ip']} ({c['classification']})" for c in observed_candidates)
            selection_reason = f"No publicly routable IP found; observed candidates are non-global: {types}."
        else:
            selection_reason = "No valid IP addresses could be extracted from the Received chain."

    return selected_ip, selection_reason, observed_candidates


def parse_auth_context(msg, relay_chain: list, from_domain: Optional[str] = None) -> dict:
    """Inspect Authentication-Results, DKIM signatures, and receiving MTA context.
    V2.6: Distinguishes claimed from verified authentication, multi-header handling,
    DKIM alignment, and boundary MTA correlation."""
    auth_headers = msg.get_all('Authentication-Results', [])
    if not auth_headers:
        return {
            'trust_status': 'MISSING',
            'authserv_id': None,
            'mechanisms': {'spf': None, 'dkim': None, 'dmarc': None},
            'evidence': 'None (Header missing)',
            'verification': 'UNVERIFIED',
            'dkim_signatures': [],
            'notes': ['No Authentication-Results header present in message']
        }

    # Topmost header is from the boundary MTA accepting the message
    auth_header = auth_headers[0]

    # Extract authserv-id (token before first semicolon)
    authserv_match = re.match(r'^\s*([^;\s]+)', auth_header)
    authserv_id = authserv_match.group(1).lower() if authserv_match else None

    # Parse individual mechanism verdicts
    mechanisms = {}
    for mech in ['spf', 'dkim', 'dmarc']:
        m = re.search(rf'{mech}=(\w+)', auth_header, re.IGNORECASE)
        mechanisms[mech] = m.group(1).lower() if m else None

    # Extract DKIM-Signature headers and their signing domains (d=)
    dkim_headers = msg.get_all('DKIM-Signature', [])
    dkim_signatures = []
    for dh in dkim_headers:
        dm = re.search(r'\bd=([\w.-]+)', dh, re.IGNORECASE)
        if dm:
            dkim_signatures.append(dm.group(1).lower())

    # Extract from_domain if not passed
    if not from_domain:
        from_addr = msg.get('From', '')
        _, from_email = email.utils.parseaddr(from_addr)
        from_domain = from_email.split('@')[-1].lower() if '@' in from_email else None

    # Inspect correlation with top receiving MTA in relay chain
    top_hop = relay_chain[0] if relay_chain else None
    mta_match = False
    if top_hop and authserv_id:
        top_raw = (top_hop.by_host or '') + ' ' + (top_hop.raw or '')
        if authserv_id in top_raw.lower():
            mta_match = True

    notes = []
    trust_status = "UNVERIFIED"

    if len(auth_headers) > 1:
        notes.append(
            f"Multiple ({len(auth_headers)}) Authentication-Results headers detected; "
            f"only boundary header is evaluated, interior headers may be upstream or forged"
        )

    if mechanisms.get('dkim') == 'pass' and not dkim_headers:
        notes.append("Authentication-Results claims dkim=pass, but no DKIM-Signature header exists in message (contradictory claim)")
    elif dkim_signatures and from_domain:
        aligned = any(
            domain_relationship(from_domain, d_sig) in (
                DomainRelation.EXACT_MATCH,
                DomainRelation.SUBDOMAIN_RELATION,
                DomainRelation.SAME_REGISTRABLE_DOMAIN
            )
            for d_sig in dkim_signatures
        )
        if not aligned:
            notes.append(
                f"DKIM signature signing domain(s) ({', '.join(dkim_signatures)}) "
                f"do not align with From domain ({from_domain}) — unaligned third-party signature"
            )

    if not mta_match and top_hop:
        notes.append(f"Authserv ID ({authserv_id}) does not match top receiving MTA ({top_hop.by_host})")
    elif mta_match:
        notes.append(f"Results claimed by boundary MTA ({authserv_id}); offline capture not cryptographically verified")
    else:
        notes.append(f"Results claimed by authserv-id ({authserv_id}); no relay hops available to correlate boundary MTA")

    return {
        'trust_status': trust_status,
        'authserv_id': authserv_id,
        'mechanisms': mechanisms,
        'dkim_signatures': dkim_signatures,
        'evidence': f"Authentication-Results ({authserv_id or 'unknown authserv'})",
        'verification': 'UNVERIFIED',
        'notes': notes
    }


def check_auth_results(msg) -> dict:
    """Backward-compatible helper to pull SPF/DKIM/DMARC verdicts."""
    auth_ctx = parse_auth_context(msg, [])
    return auth_ctx['mechanisms']


KNOWN_ESP_DOMAINS = {
    'sending-service.com', 'sendgrid.net', 'sendgrid.com', 'mailchimp.com',
    'mcsv.net', 'amazonses.com', 'createsend.com', 'hubspot.com',
    'zendesk.com', 'salesforce.com', 'mailgun.org', 'mailgun.net',
    'sparkpostmail.com', 'postmarkapp.com'
}

INCIDENTAL_PHRASES = {
    'bank': ['river bank', 'food bank', 'blood bank', 'data bank', 'snow bank', 'seed bank', 'west bank']
}


def evaluate_brand_impersonation(display_name: str, from_domain_raw: str, auth_results: dict) -> tuple:
    """Evaluate display-name brand impersonation with confidence-aware tiering.
    V2.6: Replaces binary skip with nuanced categorization and supports Unicode/homoglyphs:
      - no meaningful brand mismatch
      - weak brand mismatch (legitimate ESP + clean auth)
      - weak mismatch + authentication failure
      - strong brand mismatch (unrelated domain + passing claimed auth)
      - strong mismatch + authentication failure (critical spoofing indicator)"""
    if not display_name or not from_domain_raw:
        return None, "no meaningful brand mismatch", 0

    display_name_clean = unicodedata.normalize('NFKC', display_name).lower()
    display_name_dehomoglyph = display_name_clean.translate(HOMOGLYPH_MAP)
    from_domain_norm = _normalize_domain(from_domain_raw)
    from_domain_lower = from_domain_norm.lower()

    common_brands = ['paypal', 'microsoft', 'google', 'amazon', 'bank', 'sbi', 'hdfc']

    detected_brand = None
    for brand in common_brands:
        pattern = r'\b' + re.escape(brand) + r'\b'
        if re.search(pattern, display_name_clean) or re.search(pattern, display_name_dehomoglyph):
            # Check incidental phrases
            if brand in INCIDENTAL_PHRASES:
                if any(phrase in display_name_clean or phrase in display_name_dehomoglyph for phrase in INCIDENTAL_PHRASES[brand]):
                    continue
            detected_brand = brand
            break

    if not detected_brand:
        return None, "no meaningful brand mismatch", 0

    # Check if domain belongs to the brand using domain_relationship
    brand_domain = f"{detected_brand}.com"
    rel_with_brand = domain_relationship(from_domain_lower, brand_domain)
    if rel_with_brand in (DomainRelation.EXACT_MATCH, DomainRelation.SUBDOMAIN_RELATION, DomainRelation.SAME_REGISTRABLE_DOMAIN):
        return None, "no meaningful brand mismatch (brand belongs to sender domain)", 0

    reg_d = _registrable_domain(from_domain_lower)
    domain_root = reg_d.split('.')[0] if '.' in reg_d else reg_d
    if domain_root == detected_brand:
        return None, "no meaningful brand mismatch (brand belongs to sender domain)", 0

    # Determine if sending domain is a known ESP
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


def detect_anomalies(msg, relay_chain: list, auth_results: dict) -> tuple:
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
        # V2.5 Item 4: Reusable domain_relationship abstraction
        rel = domain_relationship(from_domain_raw, return_domain_raw)
        domain_rel_str = rel.value

        if rel == DomainRelation.UNRELATED:
            anomalies.append(
                f"MISMATCH: From domain ({from_domain_raw}) != "
                f"Return-Path domain ({return_domain_raw}) "
                f"— classic spoofing/BEC indicator"
            )
        elif rel == DomainRelation.UNKNOWN:
            anomalies.append(
                f"MALFORMED DOMAIN: could not establish relation between From domain "
                f"({from_domain_raw}) and Return-Path domain ({return_domain_raw})"
            )
    elif from_addr or return_path:
        anomalies.append(
            "MALFORMED SENDER ADDRESS: could not extract a valid email address from "
            "From/Return-Path — headers may be corrupted or deliberately obfuscated"
        )

    # V2 Fix Item 7: Distinguish SPF verdicts (FAIL vs SOFTFAIL vs NEUTRAL vs MISSING)
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

    # V2.5 Item 3: Confidence-aware brand impersonation evaluation
    brand_anom, brand_category, _ = evaluate_brand_impersonation(display_name, from_domain_raw or '', auth_results)
    if brand_anom:
        anomalies.append(brand_anom)

    return anomalies, domain_rel_str, brand_category


POSITIVE_INDICATORS = [
    'MISMATCH',
    'MALFORMED SENDER',
    'impersonates',
    'critical display-name spoofing',
    'strong brand mismatch',
    'weak mismatch + authentication failure',
    'VPN-ORIGIN',
    'NON-ROUTABLE-ORIGIN',
    'SPF check: FAIL',
    'SPF check: SOFTFAIL',
    'DKIM check: fail',
    'DMARC check: fail',
]


def compute_risk_score(anomalies: list, auth_results: dict) -> int:
    """Weighted scoring with evidence gating."""
    score = 0
    weights = {
        'MISMATCH': 30,
        'MALFORMED SENDER': 20,
        'critical display-name spoofing': 40,
        'strong brand mismatch': 25,
        'weak mismatch + authentication failure': 25,
        'weak brand mismatch': 5,
        'impersonates': 40,
        'SPF check: FAIL': 15,
        'SPF check: SOFTFAIL': 8,
        'SPF check: NEUTRAL': 5,
        'SPF check: MISSING': 15,
        'SPF check:': 15,
        'DKIM check': 15,
        'DMARC check': 15,
        'relay chain': 10,
        'header stripping': 25,
        'VPN-ORIGIN': 20,
        'NON-ROUTABLE-ORIGIN': 15,
    }
    for anomaly in anomalies:
        for key, weight in weights.items():
            if key in anomaly:
                score += weight
                break

    # Evidence gating: cap at 40 if there are zero confirmed positive threat indicators
    has_positive = any(any(pos in a for pos in POSITIVE_INDICATORS) for a in anomalies)
    if not has_positive:
        score = min(score, 40)

    return min(score, 100)


def analyze_eml(filepath: str, analyzer: OriginAnalyzer = None) -> ForensicReport:
    """End-to-end raw .eml forensic analysis."""
    with open(filepath, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    received_headers = msg.get_all('Received', [])
    relay_chain = [parse_received_header(h) for h in received_headers]

    # Receiving boundary MTA accepting the message (top hop)
    receiving_boundary = relay_chain[0].by_host if relay_chain else None

    # V2.6: Parse detailed authentication context and trust
    auth_ctx = parse_auth_context(msg, relay_chain)
    auth_results = auth_ctx['mechanisms']

    # Detect anomalies and domain relationships
    anomalies, domain_rel, brand_cat = detect_anomalies(msg, relay_chain, auth_results)

    # V2.6: Origin IP candidate selection
    selected_ip, selection_reason, observed_candidates = select_origin_ip(relay_chain)

    origin_label = None
    origin_explanation = None
    limitations = [
        "Authentication results are claimed by the message headers and were not independently verified via DNS/crypto.",
        "Selected origin IP is a candidate derived from Received header routing properties; origin attribution is UNVERIFIED in offline .eml analysis without MTA provenance logs."
    ]

    if selected_ip:
        try:
            if analyzer is None:
                analyzer = OriginAnalyzer()
            assessment = analyzer.assess(selected_ip)
            origin_label = assessment.confidence_label
            origin_explanation = assessment.explanation

            if assessment.is_vpn:
                anomalies.append(
                    f"VPN-ORIGIN: selected origin IP ({selected_ip}) is a known VPN "
                    f"exit node ({assessment.matched_range}) — true origin obscured"
                )
            elif assessment.is_datacenter:
                anomalies.append(
                    f"VPN-ORIGIN: selected origin IP ({selected_ip}) is known datacenter/"
                    f"hosting infrastructure ({assessment.matched_range}) — not a "
                    f"residential connection"
                )
            elif assessment.is_non_global:
                anomalies.append(
                    f"NON-ROUTABLE-ORIGIN: selected origin IP ({selected_ip}) is "
                    f"{assessment.non_global_reason} — should never appear in a "
                    f"legitimate real-world relay chain"
                )
        except OriginDataError as e:
            origin_label = "UNAVAILABLE"
            origin_explanation = f"Origin analysis skipped — data unavailable: {e}"
            limitations.append(f"Origin intelligence unavailable: {e}")
    else:
        if observed_candidates:
            origin_label = "NOT_ESTABLISHED"
            origin_explanation = selection_reason
            anomalies.append(
                f"NON-ROUTABLE-ORIGIN: no publicly routable origin IP found in relay chain; "
                f"observed candidates are internal/private: {', '.join(c['ip'] for c in observed_candidates)}"
            )
        else:
            origin_label = "NO_IP_FOUND"
            origin_explanation = "No IP addresses found in Received headers"

    risk_score = compute_risk_score(anomalies, auth_results)

    return ForensicReport(
        subject=msg.get('Subject', '(no subject)'),
        from_addr=msg.get('From', '(unknown)'),
        return_path=msg.get('Return-Path'),
        message_id=msg.get('Message-ID'),
        relay_chain=relay_chain,
        spf_result=auth_results.get('spf'),
        dkim_result=auth_results.get('dkim'),
        dmarc_result=auth_results.get('dmarc'),
        anomalies=anomalies,
        earliest_ip=selected_ip,
        origin_label=origin_label,
        origin_explanation=origin_explanation,
        risk_score=risk_score,
        selected_origin_ip=selected_ip,
        origin_selection_reason=selection_reason,
        observed_candidates=observed_candidates,
        domain_relation=domain_rel,
        auth_trust=auth_ctx['trust_status'],
        auth_context=auth_ctx,
        brand_assessment=brand_cat,
        limitations=limitations,
        origin_attribution="UNVERIFIED",
        origin_attribution_reason="Offline .eml analysis cannot establish which Received headers were inserted by trusted infrastructure vs fabricated by the sender.",
        receiving_boundary=receiving_boundary,
    )


def print_report(report: ForensicReport):
    """Format and display a structured forensic investigation report."""
    if report.risk_score >= 70:
        verdict = "HIGH RISK"
    elif report.risk_score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN / LOW RISK"

    print("=" * 65)
    print(f"VERDICT:    {verdict}")
    print(f"RISK SCORE: {report.risk_score}/100")
    print("=" * 65)

    print("\nAUTHENTICATION")
    spf_c = report.spf_result.upper() if report.spf_result else "MISSING"
    dkim_c = report.dkim_result.upper() if report.dkim_result else "MISSING"
    dmarc_c = report.dmarc_result.upper() if report.dmarc_result else "MISSING"
    print(f"  SPF:   {spf_c} — claimed by Authentication-Results (unverified)")
    print(f"  DKIM:  {dkim_c} — claimed by Authentication-Results (unverified)")
    print(f"  DMARC: {dmarc_c} — claimed by Authentication-Results (unverified)")
    print(f"  Trust: {report.auth_trust}")
    if report.auth_context and report.auth_context.get('notes'):
        for note in report.auth_context['notes']:
            print(f"    * {note}")

    print("\nSENDER")
    print(f"  From:         {report.from_addr}")
    print(f"  Return-Path:  {report.return_path}")
    print(f"  Relationship: {report.domain_relation or 'UNKNOWN'}")
    if report.brand_assessment:
        print(f"  Brand Status: {report.brand_assessment}")

    print("\nRELAY CHAIN")
    print(f"  Hops: {len(report.relay_chain)}")
    if report.receiving_boundary:
        print(f"  Receiving boundary:         {report.receiving_boundary}")
    if report.observed_candidates:
        print("  Observed origin candidates:")
        for c in report.observed_candidates:
            print(f"    - {c['ip']} ({c['classification']})")
    print(f"  Selected origin candidate:  {report.selected_origin_ip or 'None established'}")
    print(f"  Selection reason:           {report.origin_selection_reason}")
    print(f"  Origin attribution:         {report.origin_attribution}")
    print(f"  Attribution note:           {report.origin_attribution_reason}")

    print("\nORIGIN INTELLIGENCE")
    print(f"  Classification: {report.origin_label or 'N/A'}")
    print(f"  Details:        {report.origin_explanation or 'N/A'}")

    print(f"\nANOMALIES ({len(report.anomalies)})")
    if not report.anomalies:
        print("  None detected.")
    else:
        for a in report.anomalies:
            if any(k in a for k in ['critical display-name', 'MISMATCH', 'FAIL', 'VPN-ORIGIN', 'NON-ROUTABLE']):
                sev = "[HIGH]"
            elif any(k in a for k in ['strong brand', 'MALFORMED', 'SOFTFAIL', 'none', 'stripping', 'relay chain']):
                sev = "[MEDIUM]"
            else:
                sev = "[LOW]"
            print(f"  {sev:8} {a}")

    print("\nLIMITATIONS")
    for lim in report.limitations:
        print(f"  - {lim}")
    print("=" * 65 + "\n")


if __name__ == '__main__':
    if len(sys.argv) > 1:
        rep = analyze_eml(sys.argv[1])
        print_report(rep)
    else:
        print("Usage: python header_forensics.py <path_to_eml_file>")
