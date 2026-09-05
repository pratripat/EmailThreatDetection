"""
URL Analyzer Orchestrator
Coordinates feature extraction, SQLite cache lookups, Grok AI threat intelligence,
and heuristic score blending with graceful offline degradation.
"""

import logging
from typing import Dict, Any, List, Optional, Union
from email.message import Message

from .extractor import extract_urls_from_email, extract_urls_from_text, extract_urls_from_html
from .features import extract_features, compute_deterministic_score
from .cache import get_url_cache, URLCache
from .grok_client import get_grok_client, GrokClient, GrokUnavailableError

logger = logging.getLogger("url_analyzer")


class URLAnalyzer:
    """Orchestrator for comprehensive URL threat evaluation."""

    def __init__(
        self,
        grok_client: Optional[GrokClient] = None,
        cache: Optional[URLCache] = None,
        use_cache: bool = True,
    ):
        self.grok_client = grok_client or get_grok_client()
        self.cache = cache or get_url_cache()
        self.use_cache = use_cache

    def _merge_results(
        self,
        url: str,
        features: Dict[str, Any],
        deterministic: Dict[str, Any],
        grok_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Blend Grok AI verdict with deterministic heuristic indicators."""
        verdict = grok_result.get("verdict", "UNKNOWN")
        confidence = float(grok_result.get("confidence", 0.5))
        reason = grok_result.get("reason", "Analysis completed by Grok AI")
        det_score = deterministic["threatScore"]

        # Authority mapping
        if verdict in ["MALICIOUS", "PHISHING"]:
            reputation = "MALICIOUS"
        elif verdict == "SUSPICIOUS":
            reputation = "SUSPICIOUS"
        elif verdict == "BENIGN":
            # Safety floor: high heuristic risk cannot be marked fully SAFE
            if det_score >= 60:
                reputation = "SUSPICIOUS"
            else:
                reputation = "SAFE"
        else:
            reputation = deterministic["reputation"]

        # Base AI score calibration
        if verdict == "MALICIOUS":
            ai_base_score = 85 + int(confidence * 15)
        elif verdict == "PHISHING":
            ai_base_score = 80 + int(confidence * 20)
        elif verdict == "SUSPICIOUS":
            ai_base_score = 45 + int(confidence * 25)
        elif verdict == "BENIGN":
            ai_base_score = max(0, int((1.0 - confidence) * 25))
        else:
            ai_base_score = det_score

        # Weighted blending
        if verdict in ["MALICIOUS", "PHISHING"]:
            merged_score = max(det_score, int(0.40 * det_score + 0.60 * ai_base_score))
        elif verdict == "BENIGN":
            if det_score >= 60:
                merged_score = int(0.60 * det_score + 0.40 * ai_base_score)
            else:
                merged_score = min(det_score, int(0.45 * det_score + 0.55 * ai_base_score))
        else:
            merged_score = int(0.50 * det_score + 0.50 * ai_base_score)

        final_threat_score = max(0, min(merged_score, 100))

        # Flags merging
        combined_flags: List[str] = []
        for f in deterministic.get("flags", []):
            if f != "No suspicious patterns detected" and f not in combined_flags:
                combined_flags.append(f)

        for gf in grok_result.get("flags", []):
            if gf and gf not in combined_flags and gf.lower() != "none":
                combined_flags.append(f"Grok: {gf}")

        if not combined_flags:
            combined_flags = ["No suspicious patterns detected"]

        return {
            "url": url,
            "domain": features["domain"],
            "registeredAgeDays": -1,
            "reputation": reputation,
            "threatScore": final_threat_score,
            "flags": combined_flags,
            "redirectChain": [],
            "features": features,
            "grok_analysis": {
                "verdict": verdict,
                "confidence": round(confidence, 2),
                "reason": reason,
            },
            "cached": False,
        }

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze a single URL.
        1. Checks SQLite cache.
        2. Computes deterministic heuristic features.
        3. Invokes Grok AI if available.
        4. Blends results and saves to cache.
        """
        clean_url = url.strip()
        if not clean_url:
            return {
                "url": "",
                "domain": "unknown",
                "reputation": "SAFE",
                "threatScore": 0,
                "flags": ["Empty URL"],
                "grok_analysis": None,
                "cached": False
            }

        # 1. Cache Check
        if self.use_cache:
            cached_result = self.cache.get(clean_url)
            if cached_result:
                logger.debug(f"Cache HIT for URL: {clean_url}")
                return cached_result

        # 2. Deterministic Heuristics
        features = extract_features(clean_url)
        deterministic = compute_deterministic_score(features)

        # 3. Grok AI Analysis (with circuit breaker & fallback)
        try:
            grok_result = self.grok_client.analyze(clean_url, features)
            merged = self._merge_results(clean_url, features, deterministic, grok_result)
            if self.use_cache:
                self.cache.set(clean_url, merged)
            return merged
        except (GrokUnavailableError, Exception) as e:
            logger.debug(f"Proceeding with deterministic analysis for '{clean_url}': {e}")
            deterministic["cached"] = False
            deterministic["grok_analysis"] = None
            if self.use_cache:
                self.cache.set(clean_url, deterministic)
            return deterministic

    def analyze_urls(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Analyze a collection of URLs."""
        return [self.analyze_url(u) for u in urls]

    def analyze_email(self, eml_content: Union[str, bytes, Message]) -> Dict[str, Any]:
        """
        Extract and analyze all URLs found in an email message.
        """
        extracted = extract_urls_from_email(eml_content)
        if not extracted:
            return {
                "urls_found": [],
                "analyzed_urls": [],
                "total_urls": 0,
                "max_threat_score": 0,
                "malicious_count": 0,
                "suspicious_count": 0,
                "summary": "No URLs found in email",
            }

        analyzed = self.analyze_urls(extracted)
        max_score = max((item["threatScore"] for item in analyzed), default=0)
        malicious_count = sum(1 for item in analyzed if item["reputation"] == "MALICIOUS")
        suspicious_count = sum(1 for item in analyzed if item["reputation"] == "SUSPICIOUS")

        return {
            "urls_found": extracted,
            "analyzed_urls": analyzed,
            "total_urls": len(extracted),
            "max_threat_score": max_score,
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count,
            "summary": f"Analyzed {len(extracted)} URLs ({malicious_count} malicious, {suspicious_count} suspicious)",
        }


_default_url_analyzer: Optional[URLAnalyzer] = None


def get_url_analyzer() -> URLAnalyzer:
    """Get singleton URLAnalyzer."""
    global _default_url_analyzer
    if _default_url_analyzer is None:
        _default_url_analyzer = URLAnalyzer()
    return _default_url_analyzer
