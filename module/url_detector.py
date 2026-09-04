import re
import urllib.parse

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

def extract_urls(text: str) -> list:
    """Extracts all HTTP/HTTPS URLs from raw text/email body."""
    if not text:
        return []
    # Regular expression for full URLs
    pattern = r'https?://[^\s<>"]+'
    return list(set(re.findall(pattern, text)))

def analyze_url(url: str) -> dict:
    """Analyzes a single URL and returns an explainable risk assessment."""
    score = 0
    reasons = []

    try:
        parsed = urllib.parse.urlparse(url.strip())
        netloc = parsed.netloc.lower()
        path = parsed.path.lower()
    except Exception:
        return {
            "url": url,
            "risk_score": 100,
            "verdict": "Malicious",
            "reasons": ["Malformed or unparseable URL"]
        }

    # 1. Scheme check
    if parsed.scheme == 'http':
        score += 20
        reasons.append("Uses unencrypted HTTP instead of HTTPS (+20)")

    # 2. Raw IP address in host
    if re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$', netloc):
        score += 50
        reasons.append("Direct IP address used instead of domain name (+50)")

    # 3. Credential masking (@ symbol)
    if '@' in netloc or '@' in url:
        score += 40
        reasons.append("Contains '@' symbol (used to disguise true destination) (+40)")

    # 4. Punycode / Homograph attack (e.g. xn--)
    if 'xn--' in netloc:
        score += 45
        reasons.append("Punycode detected (potential homograph/lookalike domain) (+45)")

    # 5. URL Shorteners (FIXED)
    # Checks exact domain or subdomain, instead of a loose substring match
    if any(netloc == shortener or netloc.endswith('.' + shortener) for shortener in SHORTENERS):
        score += 25
        reasons.append("Uses URL shortener (masks final destination) (+25)")

    # 6. Suspicious TLDs
    if any(netloc.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 25
        reasons.append("Uses high-risk/abused top-level domain (+25)")

    # 7. Excessive subdomains
    domain_labels = [p for p in netloc.split('.') if p]
    if len(domain_labels) > 4:
        score += 20
        reasons.append("Excessive subdomains (+20)")

    # 8. Excessive hyphens in domain
    if netloc.count('-') >= 2:
        score += 15
        reasons.append("Multiple hyphens in domain (+15)")

    # 9. Suspicious URL length
    if len(url) > 85:
        score += 15
        reasons.append("Unusually long URL (+15)")

    # 10. Suspicious Phishing Keywords
    found_keywords = [kw for kw in SUSPICIOUS_WORDS if kw in (path + netloc)]
    if found_keywords:
        score += 25
        reasons.append(f"Contains security-sensitive keywords: {found_keywords} (+25)")

    # 11. Brand Impersonation Check
    # Extracts the probable registered domain (e.g., example.com from sub.example.com)
    registered_domain = ".".join(domain_labels[-2:]) if len(domain_labels) >= 2 else netloc
    for brand in TARGET_BRANDS:
        if brand in url.lower() and brand not in registered_domain:
            score += 40
            reasons.append(f"Possible brand impersonation ('{brand}' found outside actual domain) (+40)")
            break

    # Cap score at 100
    final_score = min(score, 100)

    # Classify verdict
    if final_score >= 60:
        verdict = "Malicious"
    elif final_score >= 30:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    return {
        "url": url,
        "risk_score": final_score,
        "verdict": verdict,
        "reasons": reasons if reasons else ["No suspicious patterns detected"]
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
    overall_score = max(r['risk_score'] for r in results)
    suspicious_count = sum(1 for r in results if r['verdict'] in ["Suspicious", "Malicious"])

    return {
        "analyzed_urls": results,
        "overall_url_score": overall_score,
        "suspicious_count": suspicious_count
    }