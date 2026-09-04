"""
Indicators of Compromise (IOC) Extraction Module
Extracts, normalizes, and deduplicates network and host indicators:
- IP addresses (observed relays, origin candidates)
- Domains (sender, return-path, URL hosts, DKIM signing domains)
- URLs (embedded links in text and HTML)
- Email addresses (From, To, Return-Path, Reply-To, body addresses)
- Attachment hashes (SHA-256 computed directly from payload bytes)
"""

import re
import email.utils
import ipaddress
from typing import Dict, List, Set, Any

from .header_forensics import _normalize_domain


EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')


def extract_iocs(
    parsed_email: Any,
    observed_ips: List[str] = None,
    analyzed_urls: List[Dict[str, Any]] = None
) -> Dict[str, List[str]]:
    """
    Extract deterministic, deduplicated IOCs from the parsed email and analyzer artifacts.
    """
    observed_ips = observed_ips or []
    analyzed_urls = analyzed_urls or []

    ips: Set[str] = set()
    domains: Set[str] = set()
    urls: Set[str] = set()
    emails: Set[str] = set()
    hashes: Set[str] = set()

    # 1. IP Addresses
    for ip in observed_ips:
        if ip:
            try:
                ip_obj = ipaddress.ip_address(ip.strip())
                ips.add(str(ip_obj))
            except ValueError:
                pass

    # 2. URLs
    if hasattr(parsed_email, 'embedded_urls'):
        for u in parsed_email.embedded_urls:
            if u:
                urls.add(u.strip())

    for u_obj in analyzed_urls:
        u_str = u_obj.get('url') if isinstance(u_obj, dict) else getattr(u_obj, 'url', None)
        if u_str:
            urls.add(u_str.strip())
        domain = u_obj.get('domain') if isinstance(u_obj, dict) else getattr(u_obj, 'domain', None)
        if domain and domain != 'unknown':
            norm_dom = _normalize_domain(domain)
            if norm_dom:
                domains.add(norm_dom)

    # 3. Email Addresses & Associated Domains
    header_addrs = []
    if hasattr(parsed_email, 'from_addr') and parsed_email.from_addr:
        header_addrs.append(parsed_email.from_addr)
    if hasattr(parsed_email, 'return_path') and parsed_email.return_path:
        header_addrs.append(parsed_email.return_path)
    if hasattr(parsed_email, 'reply_to') and parsed_email.reply_to:
        header_addrs.append(parsed_email.reply_to)
    if hasattr(parsed_email, 'to_addrs'):
        header_addrs.extend(parsed_email.to_addrs)

    for h in header_addrs:
        name, addr = email.utils.parseaddr(str(h))
        if addr and '@' in addr:
            cleaned_addr = addr.strip().lower()
            emails.add(cleaned_addr)
            dom = cleaned_addr.split('@')[-1]
            norm_dom = _normalize_domain(dom)
            if norm_dom:
                domains.add(norm_dom)

    # Search email body text for plain email addresses
    body_text = ""
    if hasattr(parsed_email, 'body_plain') and parsed_email.body_plain:
        body_text += parsed_email.body_plain + "\n"
    if hasattr(parsed_email, 'body_html') and parsed_email.body_html:
        body_text += parsed_email.body_html + "\n"

    for found_email in EMAIL_PATTERN.findall(body_text):
        cleaned_addr = found_email.strip().lower()
        emails.add(cleaned_addr)
        dom = cleaned_addr.split('@')[-1]
        norm_dom = _normalize_domain(dom)
        if norm_dom:
            domains.add(norm_dom)

    # DKIM signature domains
    if hasattr(parsed_email, 'dkim_signatures'):
        for dh in parsed_email.dkim_signatures:
            m = re.search(r'\bd=([\w.-]+)', str(dh), re.IGNORECASE)
            if m:
                norm_d = _normalize_domain(m.group(1))
                if norm_d:
                    domains.add(norm_d)

    # 4. Attachment Hashes
    if hasattr(parsed_email, 'attachments'):
        for att in parsed_email.attachments:
            h = getattr(att, 'sha256', None) or (att.get('sha256') if isinstance(att, dict) else None)
            if h and len(h) == 64:  # Valid SHA-256 hex string
                hashes.add(h.lower())

    return {
        "ipAddresses": sorted(list(ips)),
        "domains": sorted(list(domains)),
        "urls": sorted(list(urls)),
        "emailAddresses": sorted(list(emails)),
        "hashes": sorted(list(hashes)),
    }
