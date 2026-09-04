"""
Email Header Forensics Module — SIH26106 prototype
Parses raw .eml files and extracts forensic indicators:
- Relay path reconstruction (Received headers)
- SPF / DKIM / DMARC authentication results
- Anomaly flags (missing auth, relay chain irregularities, spoofed Return-Path)

This is the deterministic core — no LLM, no ML model. Pure header parsing.
"""

import email
from email import policy
from email.parser import BytesParser
import re
from dataclasses import dataclass, field
from typing import Optional


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
    risk_score: int = 0  # 0-100, higher = more suspicious


IP_PATTERN = re.compile(r'\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?')


def parse_received_header(raw_header: str) -> RelayHop:
    """Extract from/by/with/timestamp from a single Received: header."""
    hop = RelayHop(raw=raw_header)

    from_match = re.search(r'from\s+([^\s]+(?:\s+\([^)]+\))?)', raw_header)
    if from_match:
        hop.from_host = from_match.group(1)

    by_match = re.search(r'by\s+([^\s]+)', raw_header)
    if by_match:
        hop.by_host = by_match.group(1)

    with_match = re.search(r'with\s+([^\s;]+)', raw_header)
    if with_match:
        hop.with_protocol = with_match.group(1)

    ts_match = re.search(r';\s*(.+)$', raw_header.strip())
    if ts_match:
        hop.timestamp = ts_match.group(1).strip()

    return hop


def extract_ip_from_hop(hop: RelayHop) -> Optional[str]:
    """Pull the first IPv4 address out of a relay hop's 'from' field."""
    if not hop.from_host:
        return None
    match = IP_PATTERN.search(hop.from_host)
    return match.group(1) if match else None


def check_auth_results(msg) -> dict:
    """
    Parse Authentication-Results header for SPF/DKIM/DMARC verdicts.
    Real mail servers stamp this header — we're reading their verdict,
    not re-running the crypto ourselves (that requires live DNS lookups
    against the sending domain, which needs network access at demo time).
    """
    auth_header = msg.get('Authentication-Results', '')
    results = {'spf': None, 'dkim': None, 'dmarc': None}

    for mechanism in ['spf', 'dkim', 'dmarc']:
        match = re.search(rf'{mechanism}=(\w+)', auth_header, re.IGNORECASE)
        if match:
            results[mechanism] = match.group(1).lower()

    return results


def detect_anomalies(msg, relay_chain: list, auth_results: dict) -> list:
    """Rule-based anomaly detection — this IS the deterministic 'no GPT needed' core."""
    anomalies = []

    from_addr = msg.get('From', '')
    return_path = msg.get('Return-Path', '')

    from_domain_match = re.search(r'@([\w.-]+)', from_addr)
    return_domain_match = re.search(r'@([\w.-]+)', return_path or '')

    if from_domain_match and return_domain_match:
        from_domain = from_domain_match.group(1).lower()
        return_domain = return_domain_match.group(1).lower()
        if from_domain != return_domain:
            anomalies.append(
                f"MISMATCH: From domain ({from_domain}) != Return-Path domain ({return_domain}) "
                f"— classic spoofing/BEC indicator"
            )

    if auth_results.get('spf') not in ('pass',):
        anomalies.append(f"SPF check: {auth_results.get('spf') or 'MISSING'} (expected 'pass')")
    if auth_results.get('dkim') not in ('pass',):
        anomalies.append(f"DKIM check: {auth_results.get('dkim') or 'MISSING'} (expected 'pass')")
    if auth_results.get('dmarc') not in ('pass',):
        anomalies.append(f"DMARC check: {auth_results.get('dmarc') or 'MISSING'} (expected 'pass')")

    if len(relay_chain) == 0:
        anomalies.append("No Received headers found — highly unusual, possible header stripping")
    elif len(relay_chain) > 8:
        anomalies.append(f"Unusually long relay chain ({len(relay_chain)} hops) — possible relay abuse")

    display_name_match = re.search(r'^"?([^"<]+)"?\s*<', from_addr)
    if display_name_match:
        display_name = display_name_match.group(1).strip().lower()
        # crude but real signal: display name claims a different org than the actual domain
        common_brands = ['paypal', 'microsoft', 'google', 'amazon', 'bank', 'sbi', 'hdfc']
        for brand in common_brands:
            if brand in display_name and from_domain_match and brand not in from_domain_match.group(1).lower():
                anomalies.append(
                    f"Display name impersonates '{brand}' but sending domain is "
                    f"'{from_domain_match.group(1)}' — likely display-name spoofing"
                )

    return anomalies


def compute_risk_score(anomalies: list, auth_results: dict) -> int:
    """Simple weighted scoring — replace with the trained classifier's probability later."""
    score = 0
    weights = {
        'MISMATCH': 30,
        'SPF check': 15,
        'DKIM check': 15,
        'DMARC check': 15,
        'impersonates': 40,
        'relay chain': 10,
        'header stripping': 25,
    }
    for anomaly in anomalies:
        for key, weight in weights.items():
            if key in anomaly:
                score += weight
                break
    return min(score, 100)


def analyze_eml(filepath: str) -> ForensicReport:
    with open(filepath, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    received_headers = msg.get_all('Received', [])
    relay_chain = [parse_received_header(h) for h in received_headers]

    auth_results = check_auth_results(msg)
    anomalies = detect_anomalies(msg, relay_chain, auth_results)
    risk_score = compute_risk_score(anomalies, auth_results)

    earliest_ip = None
    for hop in reversed(relay_chain):  # last Received header = earliest hop (closest to sender)
        ip = extract_ip_from_hop(hop)
        if ip:
            earliest_ip = ip
            break

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
        earliest_ip=earliest_ip,
        risk_score=risk_score,
    )


def print_report(report: ForensicReport):
    print(f"{'='*60}")
    print(f"Subject: {report.subject}")
    print(f"From: {report.from_addr}")
    print(f"Return-Path: {report.return_path}")
    print(f"Relay hops: {len(report.relay_chain)}")
    print(f"Earliest traced IP: {report.earliest_ip}")
    print(f"SPF: {report.spf_result} | DKIM: {report.dkim_result} | DMARC: {report.dmarc_result}")
    print(f"\nRISK SCORE: {report.risk_score}/100")
    print(f"\nAnomalies detected ({len(report.anomalies)}):")
    for a in report.anomalies:
        print(f"  - {a}")
    print(f"{'='*60}\n")


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        report = analyze_eml(sys.argv[1])
        print_report(report)
    else:
        print("Usage: python header_forensics.py <path_to_eml_file>")
