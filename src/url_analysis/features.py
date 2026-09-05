"""
Deterministic URL Feature Extractor
Extracts lexical, structural, and heuristic indicators from URLs,
checking against brand lists, known shorteners, suspicious TLDs, and typosquatting.
"""

import re
import difflib
from urllib.parse import urlparse
from typing import Dict, Any, List, Set, Tuple

from config import settings
from src.header_forensics.domain_utils import registrable_domain, load_brand_list

# Known URL shorteners
SHORTENERS: Set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "is.gd",
    "tiny.cc", "rebrand.ly", "cutt.ly", "shorturl.at", "bl.ink", "trib.al"
}

# Abuse-prone / suspicious TLDs frequently seen in email phishing
SUSPICIOUS_TLDS: Set[str] = {
    ".xyz", ".top", ".buzz", ".loan", ".work", ".click", ".fit", ".gq",
    ".cf", ".ga", ".ml", ".tk", ".country", ".kim", ".mom", ".rest",
    ".surf", ".uno", ".zip", ".mov"
}

# Sensitive / credential harvesting keywords
SUSPICIOUS_KEYWORDS: List[str] = [
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "account", "update", "secure", "security", "banking", "authenticate",
    "password", "credential", "wallet", "invoice", "payment", "support",
    "billing", "confirm", "validation", "suspended", "unlock"
]


def check_brand_impersonation(reg_domain: str, hostname: str, brand_list: List[str]) -> List[str]:
    """
    Detect brand impersonation or typosquatting.
    Checks if a target brand appears inside a subdomain, or as a typosquatted label.
    """
    findings = []
    if not reg_domain or not hostname:
        return findings

    # Separate domain labels
    host_parts = [p.lower() for p in hostname.split(".") if p]
    reg_parts = [p.lower() for p in reg_domain.split(".") if p]
    sld = reg_parts[0] if reg_parts else ""

    for brand in brand_list:
        b_lower = brand.lower()

        # Check 1: Brand appears in subdomain while not in registered domain
        # e.g. paypal.com.attacker.com or paypal.verify-center.com
        for part in host_parts[:-len(reg_parts)]:
            if b_lower in part:
                findings.append(f"Brand '{brand}' appears in subdomain prefix '{part}' on unrelated domain '{reg_domain}'")

        # Check 2: Brand embedded in SLD with hyphen or prefix/suffix (e.g., paypal-update, secure-paypal)
        if b_lower in sld and sld != b_lower:
            findings.append(f"Brand '{brand}' embedded in second-level domain '{sld}'")

        # Check 3: Tokenized & leetspeak typosquatting (e.g. paypa1-security, micro-soft)
        tokens = [t for t in re.split(r"[-_.]", sld) if t]
        leetspeak_map = str.maketrans({'1': 'l', '0': 'o', '3': 'e', '5': 's', '@': 'a'})

        matched_brand = False
        for token in tokens + [sld]:
            normalized_token = token.translate(leetspeak_map)
            if normalized_token == b_lower and sld != b_lower:
                findings.append(f"Leetspeak/typo impersonation of brand '{brand}' in token '{token}'")
                matched_brand = True
                break
            elif len(token) >= 4 and len(b_lower) >= 4:
                sim = difflib.SequenceMatcher(None, token, b_lower).ratio()
                if 0.75 <= sim < 1.0:
                    findings.append(f"Possible typosquatting of '{brand}' in domain '{sld}' (similarity {sim:.2f})")
                    matched_brand = True
                    break

        if matched_brand:
            continue

    return findings


def extract_features(url: str) -> Dict[str, Any]:
    """Extract structural and heuristic features from a single URL."""
    cleaned_url = url.strip()
    try:
        parsed = urlparse(cleaned_url)
        netloc = parsed.netloc.lower()
        hostname = (parsed.hostname or "").lower()
        path = parsed.path.lower()
        query = parsed.query
        scheme = parsed.scheme.lower()
    except Exception:
        return {
            "url": cleaned_url,
            "domain": "unknown",
            "hostname": "",
            "is_malformed": True,
            "has_https": False,
            "has_ip": False,
            "is_shortened": False,
            "suspicious_tld": False,
            "has_punycode": False,
            "has_at_symbol": False,
            "num_subdomains": 0,
            "num_hyphens": 0,
            "url_length": len(cleaned_url),
            "num_query_params": 0,
            "has_encoded": False,
            "brand_findings": [],
            "sensitive_keywords": [],
        }

    # IP detection (IPv4 or IPv6 literal)
    has_ip = bool(re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname) or "[" in hostname)

    # Shorteners & TLDs
    is_shortened = any(hostname == s or hostname.endswith("." + s) for s in SHORTENERS)
    suspicious_tld = any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS)
    has_punycode = "xn--" in hostname
    has_at = "@" in netloc or "@" in cleaned_url

    # Registrable domain & subdomains
    reg_domain = registrable_domain(hostname) if hostname else ""
    subdomain_parts = []
    if reg_domain and hostname != reg_domain:
        prefix = hostname[:-len(reg_domain)].rstrip(".")
        subdomain_parts = [p for p in prefix.split(".") if p]

    # Brand checks
    brands = load_brand_list()
    brand_findings = check_brand_impersonation(reg_domain, hostname, brands)

    # Keyword scanning
    text_to_scan = f"{path} {query} {hostname}"
    sensitive_keywords = [
        kw for kw in SUSPICIOUS_KEYWORDS
        if re.search(r"\b" + re.escape(kw) + r"\b", text_to_scan)
    ]

    return {
        "url": cleaned_url,
        "domain": reg_domain or hostname or "unknown",
        "hostname": hostname,
        "is_malformed": False,
        "has_https": scheme == "https",
        "has_ip": has_ip,
        "is_shortened": is_shortened,
        "suspicious_tld": suspicious_tld,
        "has_punycode": has_punycode,
        "has_at_symbol": has_at,
        "num_subdomains": len(subdomain_parts),
        "num_hyphens": hostname.count("-"),
        "url_length": len(cleaned_url),
        "num_query_params": len(query.split("&")) if query else 0,
        "has_encoded": "%" in path or "%" in query,
        "brand_findings": brand_findings,
        "sensitive_keywords": sensitive_keywords,
    }


def compute_deterministic_score(features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculates heuristic threat score (0-100), reputation, and security flags.
    No network calls required.
    """
    url = features.get("url", "")
    if features.get("is_malformed"):
        return {
            "url": url,
            "domain": "unknown",
            "reputation": "MALICIOUS",
            "threatScore": 100,
            "flags": ["Malformed or unparseable URL"],
            "features": features
        }

    score = 0
    flags: List[str] = []

    if not features["has_https"]:
        score += 20
        flags.append("Uses unencrypted HTTP instead of HTTPS (+20)")

    if features["has_ip"]:
        score += 50
        flags.append("Direct IP address used instead of domain name (+50)")

    if features["has_at_symbol"]:
        score += 40
        flags.append("Contains '@' symbol (credential masking) (+40)")

    if features["has_punycode"]:
        score += 45
        flags.append("Punycode detected (potential homograph attack) (+45)")

    if features["is_shortened"]:
        score += 25
        flags.append("Uses URL shortener (masks destination) (+25)")

    if features["suspicious_tld"]:
        score += 25
        flags.append("Uses suspicious / high-abuse top-level domain (+25)")

    if features["num_subdomains"] > 3:
        score += 20
        flags.append("Excessive subdomains (+20)")

    if features["num_hyphens"] >= 2:
        score += 15
        flags.append("Multiple hyphens in domain (+15)")

    if features["url_length"] > 85:
        score += 15
        flags.append("Unusually long URL (+15)")

    if features["num_query_params"] > 5:
        score += 10
        flags.append("Excessive query parameters (+10)")

    if features["sensitive_keywords"]:
        score += 25
        flags.append(f"Contains security-sensitive keywords: {features['sensitive_keywords']} (+25)")

    if features["brand_findings"]:
        score += 40
        flags.append(f"Possible brand impersonation: {features['brand_findings'][0]} (+40)")

    final_score = min(score, 100)

    if final_score >= 60:
        reputation = "MALICIOUS"
    elif final_score >= 30:
        reputation = "SUSPICIOUS"
    else:
        reputation = "SAFE"

    return {
        "url": url,
        "domain": features["domain"],
        "reputation": reputation,
        "threatScore": final_score,
        "flags": flags if flags else ["No suspicious patterns detected"],
        "features": features
    }
