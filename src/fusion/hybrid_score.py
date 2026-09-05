"""
Hybrid Threat Score Fusion Engine
Synthesizes signals from Header Forensics, Origin Infrastructure Analysis,
and Grok AI URL Threat Intelligence into a unified calibrated threat assessment.
"""

from typing import Dict, Any, List, Optional
from config import settings


def classify_tier(score: int) -> str:
    """Classify 0-100 threat score into operational tiers."""
    if score >= settings.THREAT_TIER_CRITICAL:
        return "CRITICAL"
    if score >= settings.THREAT_TIER_HIGH:
        return "HIGH"
    if score >= settings.THREAT_TIER_SUSPICIOUS:
        return "SUSPICIOUS"
    return "LOW"


def fuse_threat_intelligence(
    header_data: Optional[Dict[str, Any]] = None,
    origin_data: Optional[Dict[str, Any]] = None,
    url_data: Optional[Dict[str, Any]] = None,
    content_data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Combines multi-vector evidence into a cohesive hybrid score and executive summary.

    Weights:
    - URL Intelligence: 40% (direct payload risk)
    - Header Forensics: 35% (identity spoofing & auth failures)
    - Origin IP Analysis: 15% (infrastructure legitimacy)
    - Content/Heuristics: 10% (urgency/action cues)
    """
    header_data = header_data or {}
    origin_data = origin_data or {}
    url_data = url_data or {}
    content_data = content_data or {}

    header_score = int(header_data.get("risk_score", 0))
    origin_score = int(origin_data.get("risk_score", 0))
    url_max_score = int(url_data.get("max_threat_score", 0))
    content_score = int(content_data.get("risk_score", 0))

    # Weight distribution
    w_url = 0.40
    w_header = 0.35
    w_origin = 0.15
    w_content = 0.10

    weighted_score = (
        (url_max_score * w_url) +
        (header_score * w_header) +
        (origin_score * w_origin) +
        (content_score * w_content)
    )

    # Escalation Rules:
    # 1. Confirmed malicious URL or active phishing URL directly escalates threat floor
    malicious_url_count = url_data.get("malicious_count", 0)
    suspicious_url_count = url_data.get("suspicious_count", 0)

    if malicious_url_count > 0 or url_max_score >= 85:
        weighted_score = max(weighted_score, 85.0)

    # 2. Critical identity spoofing + SPF/DKIM fail escalates floor
    header_anomalies = header_data.get("anomalies", [])
    has_critical_spoofing = any(
        "critical display-name spoofing" in a or "impersonates" in a
        for a in header_anomalies
    )
    if has_critical_spoofing and header_score >= 60:
        weighted_score = max(weighted_score, 75.0)

    # 3. Compound risk: VPN origin + suspicious URL + SPF fail
    if origin_data.get("is_vpn") and (suspicious_url_count > 0 or url_max_score >= 40):
        weighted_score = max(weighted_score, 70.0)

    final_score = int(min(100, max(0, round(weighted_score))))
    tier = classify_tier(final_score)

    # Collect key indicators
    key_indicators: List[str] = []

    for anom in header_anomalies[:5]:
        key_indicators.append(f"Header: {anom}")

    for reason in origin_data.get("reasons", []):
        if "No IP provided" not in reason:
            key_indicators.append(f"Origin IP: {reason}")

    for u in url_data.get("analyzed_urls", []):
        if u.get("reputation") in ["MALICIOUS", "SUSPICIOUS"]:
            grok_info = u.get("grok_analysis") or {}
            verdict = grok_info.get("verdict", u.get("reputation"))
            key_indicators.append(f"URL ({verdict}): {u.get('url')} - {', '.join(u.get('flags', []))[:80]}")

    # Determine primary threat vector
    if url_max_score >= 70 or malicious_url_count > 0:
        primary_vector = "Malicious URL / Credential Harvesting Link"
    elif has_critical_spoofing:
        primary_vector = "Executive / Brand Display-Name Spoofing"
    elif header_score >= 60:
        primary_vector = "Authentication Failure & Header Manipulation"
    elif origin_data.get("is_vpn") or origin_data.get("is_datacenter"):
        primary_vector = "Anomalous Hosting / Infrastructure Origin"
    else:
        primary_vector = "Benign / Low Anomaly"

    # Prescriptive recommendation
    if tier == "CRITICAL":
        recommendation = "QUARANTINE IMMEDIATELY: High-confidence phishing or malicious payload detected. Block sender and extracted URLs."
    elif tier == "HIGH":
        recommendation = "BLOCK & REPORT: Strong indicators of identity spoofing or suspicious links. Do not click links or reply."
    elif tier == "SUSPICIOUS":
        recommendation = "PROCEED WITH CAUTION: Anomalies detected in email headers or destination URLs. Verify out-of-band."
    else:
        recommendation = "ALLOW: No significant security threats detected across headers, infrastructure, or embedded links."

    # Calibrated confidence
    confidence = 0.85
    if url_data.get("analyzed_urls"):
        # Factor in AI confidence if available
        ai_confs = [
            u.get("grok_analysis", {}).get("confidence", 0.7)
            for u in url_data.get("analyzed_urls", [])
            if u.get("grok_analysis")
        ]
        if ai_confs:
            confidence = round(sum(ai_confs) / len(ai_confs), 2)

    return {
        "final_threat_score": final_score,
        "threat_tier": tier,
        "confidence": confidence,
        "primary_threat_vector": primary_vector,
        "component_scores": {
            "header_forensics": header_score,
            "origin_infrastructure": origin_score,
            "url_intelligence": url_max_score,
            "content_heuristics": content_score,
        },
        "key_indicators": key_indicators if key_indicators else ["No notable security threats identified"],
        "recommendation": recommendation,
    }
