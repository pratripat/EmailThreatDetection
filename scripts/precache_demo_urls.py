"""
Pre-cache Demo URLs Script
Pre-warms the SQLite URL threat database (data/cache/url_checks.sqlite)
with realistic security evaluations for demo and stress testing.
"""

import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.url_analysis.analyzer import get_url_analyzer
from src.url_analysis.cache import get_url_cache

DEMO_URLS = [
    # Safe domains
    "https://www.google.com",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://github.com",
    # Phishing / Brand impersonation
    "https://paypa1-security-verify.com/login",
    "http://chase-online-update.top/auth",
    "http://netflix-billing-update.buzz/account",
    # Malware / Raw IP
    "http://185.220.101.5/invoice.zip",
    "http://45.154.255.89/malware.exe",
    # Shortener masking
    "https://bit.ly/secure-login-39x",
]


def precache_all():
    print(f"[*] Pre-caching {len(DEMO_URLS)} demo URLs into SQLite...")
    analyzer = get_url_analyzer()
    cache = get_url_cache()

    for url in DEMO_URLS:
        print(f"  -> Processing: {url}")
        result = analyzer.analyze_url(url)
        print(f"     [Result] {result['reputation']} (Score: {result['threatScore']}/100)")

    print("[+] Pre-caching complete!")


if __name__ == "__main__":
    precache_all()
