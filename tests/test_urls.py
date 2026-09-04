import json
import sys
import os

# Ensure modules folder can be imported when running from tests/
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from module.url_detector import analyze_urls

# 10 Diverse Test Cases (Benign, Phishing, IP-based, Punycode, Shortened)
test_urls = [
    # Clean URLs
    "https://www.google.com/search?q=cybersecurity",
    "https://aws.amazon.com/console/",
    "https://en.wikipedia.org/wiki/Phishing",
    
    # Phishing / Malicious indicators
    "http://paypal-security-update.account-verify.xyz/login",  # HTTP + Brand spoof + Keywords + Bad TLD
    "http://192.168.1.100/admin/login.php",                   # Raw IP + HTTP + Keyword
    "https://xn--appl-43d.com/iphone-support",                 # Punycode (homograph attack)
    "https://bit.ly/3xYz123",                                 # URL Shortener
    "http://chase-bank.secure-auth-login.com/signin",          # Brand spoof + Subdomains + Keywords
    "https://user:password@malicious-redirect.com/update",     # Credential masking (@)
    "http://free-giftcards.win-prizes-today.click/verify"      # Bad TLD + Multiple hyphens + Keyword
]

def run_tests():
    print("=" * 60)
    print("RUNNING URL THREAT ANALYSIS TEST SUITE")
    print("=" * 60)

    summary = analyze_urls(test_urls)

    for item in summary["analyzed_urls"]:
        print(f"\nURL:    {item['url']}")
        print(f"Score:  {item['risk_score']}/100 [{item['verdict']}]")
        print(f"Flags:  {', '.join(item['reasons'])}")

    print("\n" + "=" * 60)
    print(f"Total URLs Tested:     {len(test_urls)}")
    print(f"Flagged (Risk >= 30):  {summary['suspicious_count']}")
    print(f"Overall Max Threat:    {summary['overall_url_score']}/100")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()