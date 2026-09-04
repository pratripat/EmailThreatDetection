"""
URL Threat Analysis Module — Backend Analyzer
Integrates heuristic URL analysis, PSL-aware domain resolution, typosquatting
brand impersonation detection, and HTML/text URL extraction.
"""

import re
import difflib
import urllib.parse
from pathlib import Path
from typing import Optional, List, Dict, Tuple, Any
import tldextract

# ---------------------------------------------------------------------------
# Offline-safe PSL extractor.
# Checks backend/data/tld_cache, data/tld_cache, or falls back to bundled snapshot.
# ---------------------------------------------------------------------------
_tld_cache = None
for candidate in [
    Path(__file__).resolve().parent.parent.parent / 'data' / 'tld_cache',
    Path.cwd() / 'backend' / 'data' / 'tld_cache',
    Path.cwd() / 'data' / 'tld_cache',
]:
    if candidate.exists():
        _tld_cache = str(candidate)
        break

if _tld_cache:
    _TLD_EXTRACTOR = tldextract.TLDExtract(cache_dir=_tld_cache, suffix_list_urls=())
else:
    _TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

# Known indicators & lists
SUSPICIOUS_WORDS = [
    'login', 'verify', 'secure', 'account', 'update',
    'payment', 'banking', 'confirm', 'wallet', 'signin'
]

TARGET_BRANDS = [
    'paypal', 'google', 'microsoft', 'apple', 'amazon',
    'netflix', 'chase', 'wellsfargo', 'facebook', 'instagram'
]

SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd',
    'buff.ly', 'ow.ly', 'rb.gy'
]

SUSPICIOUS_TLDS = [
    '.xyz', '.top', '.work', '.click', '.fit',
    '.tk', '.ml', '.ga', '.cf', '.gq', '.rest'
]

FUZZY_MATCH_THRESHOLD = 0.75  # similarity ratio floor for typosquat detection


def extract_urls(text: str) -> list:
    """Extracts all HTTP/HTTPS URLs from raw text/email body."""
    if not text:
        return []
    pattern = r'https?://[^\s<>"\'\)]+'
    matches = re.findall(pattern, text)
    # Deduplicate preserving order
    seen = set()
    res = []
    for m in matches:
        cleaned = m.rstrip('.,;:')
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            res.append(cleaned)
    return res


def extract_urls_from_html(html_content: str) -> list:
    """Extracts all HTTP/HTTPS URLs from HTML content (both href attributes and plain text)."""
    if not html_content:
        return []
    urls = []
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html_content, 'html.parser')
        for a in soup.find_all('a', href=True):
            href = a['href'].strip()
            if href.startswith(('http://', 'https://')):
                urls.append(href)
    except Exception:
        pass

    # Also capture plain text URLs in HTML
    urls.extend(extract_urls(html_content))

    # Deduplicate preserving order
    seen = set()
    res = []
    for u in urls:
        cleaned = u.rstrip('.,;:')
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            res.append(cleaned)
    return res


def get_registered_domain(hostname: str) -> tuple:
    """
    Returns (registered_domain, subdomain) using the Public Suffix List,
    handling multi-part suffixes like .co.in / .co.uk / .com.au correctly.
    """
    if not hostname:
        return "", ""
    ext = _TLD_EXTRACTOR(hostname)
    if not ext.domain:
        return hostname, ""
    registered_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    return registered_domain, ext.subdomain


def check_brand_impersonation(registered_domain: str, subdomain: str, brands: list) -> list:
    """
    Two-tier brand check:
      1. Exact brand name in subdomain of unrelated domain (e.g. amazon.verify-login.xyz)
      2. Fuzzy match on domain root for typosquats (amaz0n.com, paypa1.com)
    """
    findings = []
    if not registered_domain:
        return findings

    domain_root = registered_domain.split('.')[0].lower()
    subdomain = (subdomain or "").lower()

    for brand in brands:
        if domain_root == brand:
            continue  # Legitimate brand domain root

        if brand in subdomain:
            findings.append(
                f"Brand '{brand}' found in subdomain of unrelated domain "
                f"('{subdomain}.{registered_domain}')"
            )
            continue

        similarity = difflib.SequenceMatcher(None, domain_root, brand).ratio()
        if FUZZY_MATCH_THRESHOLD <= similarity < 1.0:
            findings.append(
                f"Domain '{domain_root}' closely resembles brand '{brand}' "
                f"(similarity={similarity:.2f})"
            )

    return findings


def analyze_url(url: str) -> dict:
    """Analyzes a single URL and returns an explainable risk assessment."""
    score = 0
    reasons = []

    try:
        parsed = urllib.parse.urlparse(url.strip())
        hostname = (parsed.hostname or "").lower()
        netloc = parsed.netloc.lower()
        path = parsed.path.lower()
    except Exception:
        return {
            "url": url,
            "domain": "unknown",
            "registeredAgeDays": None,
            "reputation": "MALICIOUS",
            "threatScore": 100,
            "risk_score": 100,
            "verdict": "Malicious",
            "flags": ["Malformed or unparseable URL"],
            "reasons": ["Malformed or unparseable URL"],
            "redirectChain": []
        }

    # 1. Scheme check
    if parsed.scheme == 'http':
        score += 20
        reasons.append("Uses unencrypted HTTP instead of HTTPS (+20)")

    # 2. Raw IP address in host
    if re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
        score += 50
        reasons.append("Direct IP address used instead of domain name (+50)")

    # 3. Credential masking (@ symbol)
    if '@' in netloc or '@' in url:
        score += 40
        reasons.append("Contains '@' symbol (used to disguise true destination) (+40)")

    # 4. Punycode / Homograph attack (e.g. xn--)
    if 'xn--' in hostname:
        score += 45
        reasons.append("Punycode detected (potential homograph/lookalike domain) (+45)")

    # 5. URL Shorteners
    if any(hostname == shortener or hostname.endswith('.' + shortener) for shortener in SHORTENERS):
        score += 25
        reasons.append("Uses URL shortener (masks final destination) (+25)")

    # 6. Suspicious TLDs
    if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 25
        reasons.append("Uses high-risk/abused top-level domain (+25)")

    # PSL-aware registered domain + subdomain
    registered_domain, subdomain = get_registered_domain(hostname)
    subdomain_labels = [p for p in subdomain.split('.') if p] if subdomain else []

    # 7. Excessive subdomains
    if len(subdomain_labels) > 3:
        score += 20
        reasons.append("Excessive subdomains (+20)")

    # 8. Excessive hyphens in domain
    if hostname.count('-') >= 2:
        score += 15
        reasons.append("Multiple hyphens in domain (+15)")

    # 9. Suspicious URL length
    if len(url) > 85:
        score += 15
        reasons.append("Unusually long URL (+15)")

    # 10. Suspicious Phishing Keywords
    found_keywords = [
        kw for kw in SUSPICIOUS_WORDS
        if re.search(r'\b' + re.escape(kw) + r'\b', path + ' ' + hostname)
    ]
    if found_keywords:
        score += 25
        reasons.append(f"Contains security-sensitive keywords: {found_keywords} (+25)")

    # 11. Brand Impersonation Check
    brand_findings = check_brand_impersonation(registered_domain, subdomain, TARGET_BRANDS)
    if brand_findings:
        score += 40
        reasons.append(f"Possible brand impersonation: {brand_findings[0]} (+40)")

    final_score = min(score, 100)

    # Classify verdict
    if final_score >= 60:
        verdict = "Malicious"
        reputation = "MALICIOUS"
    elif final_score >= 30:
        verdict = "Suspicious"
        reputation = "SUSPICIOUS"
    else:
        verdict = "Safe"
        reputation = "SAFE"

    flags = reasons if reasons else ["No suspicious patterns detected"]

    return {
        "url": url,
        "domain": registered_domain or hostname or "unknown",
        "registeredAgeDays": None,  # V3 WHOIS intelligence pending
        "reputation": reputation,
        "threatScore": final_score,
        "risk_score": final_score,  # backward compatibility
        "verdict": verdict,         # backward compatibility
        "flags": flags,
        "reasons": flags,           # backward compatibility
        "redirectChain": []         # V3 live network trace pending
    }


def analyze_urls(urls: list) -> dict:
    """Aggregates analysis for a batch of URLs."""
    if not urls:
        return {
            "analyzed_urls": [],
            "overall_url_score": 0,
            "suspicious_count": 0,
            "summary": "No URLs provided"
        }

    results = [analyze_url(u) for u in urls]
    overall_score = max((r['risk_score'] for r in results), default=0)
    suspicious_count = sum(1 for r in results if r['verdict'] in ["Suspicious", "Malicious"])

    return {
        "analyzed_urls": results,
        "overall_url_score": overall_score,
        "suspicious_count": suspicious_count
    }
