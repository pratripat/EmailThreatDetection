"""
Authentication Trust Analysis
Inspects Authentication-Results headers, DKIM-Signature headers, and correlation with boundary MTA.
"""

import re
import email.utils
from typing import Optional, List, Dict, Any

from .domain_utils import domain_relationship, DomainRelation


def parse_auth_context(msg, relay_chain: Optional[list] = None, from_domain: Optional[str] = None) -> Dict[str, Any]:
    """Inspect Authentication-Results, DKIM signatures, and receiving MTA context."""
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


def check_auth_results(msg_or_ctx) -> Dict[str, Optional[str]]:
    """Helper to pull SPF/DKIM/DMARC verdicts from either Message or parsed context dict."""
    if isinstance(msg_or_ctx, dict) and 'mechanisms' in msg_or_ctx:
        return msg_or_ctx['mechanisms']
    auth_ctx = parse_auth_context(msg_or_ctx, [])
    return auth_ctx['mechanisms']
