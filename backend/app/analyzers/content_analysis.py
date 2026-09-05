"""
Content Analysis Module — Baseline Heuristic Content Engine
Analyzes email subject, plain text, and HTML body for social engineering indicators,
urgent action coercion, credential solicitation, and financial manipulation.
Explicitly functions as a deterministic baseline analyzer without fabricating
ML confidence percentages or synthetic SHAP values (V3 ML/NLP model pending).
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Tuple


# Known social engineering keyword taxonomies
INTENT_PATTERNS = {
    "Credential Harvesting": [
        r'\b(?:verify|confirm|validate|update)\s+(?:your\s+)?(?:account|password|credentials|identity|profile)\b',
        r'\b(?:login|sign\s*in)\s+(?:immediately|to\s+verify|here)\b',
        r'\b(?:unauthorized|unusual)\s+(?:access|login|activity)\s+(?:detected)?\b',
    ],
    "Urgent Coercion": [
        r'\b(?:urgent|immediately|within\s+24\s+hours|action\s+required|suspended|limited|restricted|terminated)\b',
        r'\bfailure\s+to\s+respond\s+will\s+result\b',
        r'\baccount\s+has\s+been\s+(?:limited|suspended|locked|flagged)\b',
    ],
    "Financial Solicitation": [
        r'\b(?:wire\s+transfer|gift\s+card|bitcoin|crypto|cryptocurrency|direct\s+deposit)\b',
        r'\b(?:overdue|unpaid)\s+(?:invoice|payment|bill)\b',
        r'\bclaim\s+your\s+(?:prize|reward|refund|settlement)\b',
    ],
    "Executive Impersonation": [
        r'\b(?:confidential\s+request|wire\s+urgently|are\s+you\s+at\s+your\s+desk|need\s+a\s+favor)\b',
    ]
}


SIGNAL_TYPE_MAP = {
    "Urgent Coercion": "Urgency signal",
    "Credential Harvesting": "Credential request",
    "Financial Solicitation": "Financial coercion",
    "Executive Impersonation": "Security impersonation",
}


@dataclass
class ContentAnalysisResult:
    classification: str = "BENIGN"
    confidence: float = 0.0  # Baseline deterministic analyzer (no fake ML confidence)
    intents: List[str] = field(default_factory=list)
    suspicious_phrases: List[Dict[str, str]] = field(default_factory=list)
    feature_contributions: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: int = 0
    analysis_notes: List[str] = field(default_factory=list)


def analyze_content(
    subject: str = "",
    body_plain: str = "",
    body_html: str = ""
) -> ContentAnalysisResult:
    """
    Perform deterministic heuristic content analysis on email text.
    Returns ContentAnalysisResult conforming to the contentAi schema.
    """
    result = ContentAnalysisResult()
    combined_text = f"{subject}\n{body_plain}\n{body_html}".lower()

    detected_intents = set()
    found_phrases = []
    seen_phrases = set()

    for intent, patterns in INTENT_PATTERNS.items():
        signal_type = SIGNAL_TYPE_MAP.get(intent, "Urgency signal")
        for pattern in patterns:
            matches = re.findall(pattern, combined_text, re.IGNORECASE)
            if matches:
                detected_intents.add(intent)
                for m in matches:
                    if isinstance(m, str) and m not in seen_phrases:
                        seen_phrases.add(m)
                        found_phrases.append({
                            "phrase": m,
                            "signalType": signal_type
                        })

    result.intents = sorted(list(detected_intents))
    result.suspicious_phrases = found_phrases[:10]  # Top findings

    # Determine baseline heuristic risk score (0-100)
    score = 0
    if "Urgent Coercion" in detected_intents:
        score += 35
    if "Credential Harvesting" in detected_intents:
        score += 45
    if "Financial Solicitation" in detected_intents:
        score += 30
    if "Executive Impersonation" in detected_intents:
        score += 30

    result.risk_score = min(score, 100)

    # Classification enum strictly: 'PHISHING' | 'SPOOFING' | 'BEC_FRAUD' | 'BENIGN' | 'MALWARE_DROP'
    if "Credential Harvesting" in detected_intents or ("Urgent Coercion" in detected_intents and result.risk_score >= 35):
        result.classification = "PHISHING"
    elif "Executive Impersonation" in detected_intents or "Financial Solicitation" in detected_intents:
        result.classification = "BEC_FRAUD"
    elif result.risk_score >= 40:
        result.classification = "SPOOFING"
    else:
        result.classification = "BENIGN"

    # Honest confidence representation: baseline heuristic confidence
    # We do NOT claim high confidence (e.g. 94.7%) without a real fine-tuned transformer model.
    if result.risk_score > 0:
        result.confidence = 0.50  # Moderate heuristic confidence
        result.analysis_notes.append("Classification derived from deterministic baseline pattern matcher; ML transformer fine-tuning scheduled for V3.")
    else:
        result.confidence = 0.0   # No positive indicators detected
        result.analysis_notes.append("No suspicious content patterns identified by baseline analyzer.")

    # Feature contributions: empty list to avoid fabricating synthetic SHAP values
    result.feature_contributions = []

    return result
