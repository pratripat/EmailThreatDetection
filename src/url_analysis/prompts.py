"""
Prompt Templates and Response Parsers for Grok AI Threat Intelligence
Provides structured prompting and robust multi-format parsing (Key-Value and JSON).
"""

import re
import json
from typing import Dict, Any, List


SYSTEM_PROMPT = """You are an elite cybersecurity specialist and automated email threat forensics analyst.
Your task is to analyze URLs extracted from emails for threats including phishing, credential harvesting, malware delivery, and domain spoofing.
You evaluate the URL and its technical indicators and classify it strictly into one of:
- BENIGN (safe legitimate service)
- PHISHING (credential theft, impersonation)
- MALICIOUS (malware distribution, exploits, ransomware)
- SUSPICIOUS (anomalous indicators, questionable redirectors, disposable domains)

Be precise, objective, and provide a calibrated confidence score and clear, concise reasoning."""


def build_analysis_prompt(url: str, features: Dict[str, Any]) -> str:
    """Construct structured user prompt with technical heuristic indicators."""
    indicators: List[str] = []

    if not features.get("has_https", False):
        indicators.append("No HTTPS (plain unencrypted HTTP)")
    if features.get("has_ip", False):
        indicators.append(f"Raw IP address host: {features.get('hostname')}")
    if features.get("has_punycode", False):
        indicators.append("Punycode / homoglyph domain detected")
    if features.get("has_at_symbol", False):
        indicators.append("Embedded '@' symbol (credential or auth trick)")
    if features.get("is_shortened", False):
        indicators.append("URL shortener service (destination masked)")
    if features.get("suspicious_tld", False):
        indicators.append("Abuse-prone / suspicious top-level domain")
    if features.get("brand_findings"):
        indicators.append(f"Brand impersonation cues: {'; '.join(features['brand_findings'])}")
    if features.get("sensitive_keywords"):
        indicators.append(f"Sensitive keywords in URL: {', '.join(features['sensitive_keywords'])}")
    if features.get("num_subdomains", 0) > 3:
        indicators.append(f"Excessive subdomains: {features['num_subdomains']}")
    if features.get("num_hyphens", 0) >= 2:
        indicators.append(f"Multiple hyphens in domain: {features['num_hyphens']}")

    indicators_str = "\n".join(f"- {ind}" for ind in indicators) if indicators else "- No heuristic anomalies detected"

    return f"""Analyze this URL for phishing, credential harvesting, malware delivery, or benign intent:

URL: {url}
Domain: {features.get('domain', 'unknown')}
Technical Indicators:
{indicators_str}

Respond in this EXACT key-value format:
VERDICT: [BENIGN, PHISHING, MALICIOUS, or SUSPICIOUS]
CONFIDENCE: [0.0 to 1.0]
REASON: [1-2 sentences technical reasoning]
FLAGS: [comma-separated security flags or 'None']"""


def parse_grok_response(response_text: str) -> Dict[str, Any]:
    """Parse Grok output (handles both JSON and standard key-value blocks)."""
    result = {
        "verdict": "UNKNOWN",
        "confidence": 0.5,
        "reason": "Analysis completed by Grok AI",
        "flags": [],
        "raw_response": response_text
    }

    if not response_text:
        return result

    # 1. Attempt JSON parsing if present
    json_match = re.search(r"\{[\s\S]*\}", response_text)
    if json_match:
        try:
            data = json.loads(json_match.group(0))
            raw_v = str(data.get("verdict", "")).strip().upper()
            if raw_v in ["BENIGN", "PHISHING", "MALICIOUS", "SUSPICIOUS"]:
                result["verdict"] = raw_v
            
            raw_conf = data.get("confidence", 0.5)
            try:
                conf = float(raw_conf)
                if conf > 1.0:
                    conf = conf / 100.0
                result["confidence"] = max(0.0, min(round(conf, 2), 1.0))
            except Exception:
                pass

            if "reason" in data:
                result["reason"] = str(data["reason"]).strip()
            if "flags" in data:
                fl = data["flags"]
                if isinstance(fl, list):
                    result["flags"] = [str(f).strip() for f in fl if str(f).strip().lower() != "none"]
                elif isinstance(fl, str) and fl.lower() != "none":
                    result["flags"] = [f.strip() for f in fl.split(",") if f.strip()]
            return result
        except Exception:
            pass

    # 2. Key-value line parsing
    for line in response_text.strip().split("\n"):
        line = line.strip()
        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        key = key.strip().upper()
        value = value.strip()

        if key == "VERDICT":
            v_clean = re.sub(r"[^A-Z]", "", value.upper())
            for candidate in ["PHISHING", "MALICIOUS", "SUSPICIOUS", "BENIGN"]:
                if candidate in v_clean:
                    result["verdict"] = candidate
                    break
        elif key == "CONFIDENCE":
            conf_match = re.search(r"(\d+(?:\.\d+)?)", value)
            if conf_match:
                try:
                    num = float(conf_match.group(1))
                    if num > 1.0:
                        num = num / 100.0
                    result["confidence"] = max(0.0, min(round(num, 2), 1.0))
                except Exception:
                    pass
        elif key == "REASON":
            result["reason"] = value.strip("[]\"' ")
        elif key == "FLAGS":
            cleaned = value.strip("[]\"' ")
            if cleaned.lower() not in ["none", "n/a", "no flags", ""]:
                result["flags"] = [f.strip() for f in cleaned.split(",") if f.strip()]

    return result
