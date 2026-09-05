"""
Forensic Risk Scoring
Calculates risk scores based on detected anomalies, weighted rules, and evidence gating.
"""

from typing import List, Dict

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


def compute_risk_score(anomalies: List[str], auth_results: dict) -> int:
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
