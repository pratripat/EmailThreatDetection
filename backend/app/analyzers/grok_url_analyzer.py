"""
Grok-powered URL Analyzer Module
Combines deterministic heuristic checks (PSL resolution, brand impersonation,
suspicious TLDs, Punycode, raw IP hosts) with Grok AI (xAI grok-4.6 via OpenAI-compatible endpoint)
for explainable URL threat classification with graceful degradation.
"""

import os
import re
import json
import logging
from typing import Set, List, Dict, Any, Optional, Union
from urllib.parse import urlparse
import email
from email import message_from_string, message_from_bytes
from email.message import Message

from .url_analysis import (
    get_registered_domain,
    check_brand_impersonation,
    extract_urls as base_extract_urls,
    extract_urls_from_html as base_extract_urls_from_html,
    SHORTENERS,
    SUSPICIOUS_TLDS,
    TARGET_BRANDS,
    SUSPICIOUS_WORDS,
)

logger = logging.getLogger(__name__)

# Fallback lists if needed
URL_SHORTENERS = set(SHORTENERS)
KNOWN_SUSPICIOUS_TLDS = set(SUSPICIOUS_TLDS)


class GrokURLAnalyzer:
    """
    Grok-powered URL analysis engine that enhances deterministic heuristic checks
    with xAI Grok (grok-4.6) threat intelligence and graceful offline degradation.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "https://api.x.ai/v1",
        model: str = "grok-4.6",
    ):
        # Support OPENAI_API_KEY (primary format: xai-...), fallback to GROK_API_KEY / XAI_API_KEY
        self.api_key = (
            api_key
            or os.getenv("OPENAI_API_KEY")
            or os.getenv("GROK_API_KEY")
            or os.getenv("XAI_API_KEY")
        )
        self.base_url = os.getenv("GROK_BASE_URL", base_url)
        self.model = os.getenv("GROK_MODEL", model)
        self.enabled = False
        self.client = None

        if self.api_key and self.api_key.strip():
            # Treat default placeholder as disabled unless it's a real key
            if self.api_key.strip().startswith("xai-example-key"):
                logger.info("OPENAI_API_KEY is an example placeholder. Grok analyzer running in deterministic mode.")
                self.enabled = False
            else:
                try:
                    from openai import OpenAI
                    self.client = OpenAI(
                        api_key=self.api_key.strip(),
                        base_url=self.base_url,
                        timeout=15.0,
                    )
                    self.enabled = True
                    logger.info(f"Grok URL Analyzer initialized with model {self.model} at {self.base_url}")
                except Exception as e:
                    logger.warning(f"Failed to initialize OpenAI client for Grok: {e}. Degrading to deterministic mode.")
                    self.enabled = False
        else:
            logger.info("OPENAI_API_KEY not found - Grok URL Analyzer running in deterministic fallback mode")

    # --------------------------------------------------------------------------
    # URL Extraction
    # --------------------------------------------------------------------------
    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """Extract HTTP/HTTPS URLs from raw text."""
        return base_extract_urls(text)

    @staticmethod
    def extract_urls_from_html(html_content: str) -> List[str]:
        """Extract HTTP/HTTPS URLs from HTML content."""
        return base_extract_urls_from_html(html_content)

    def extract_urls_from_email(self, eml_content: Union[str, bytes, Message]) -> List[str]:
        """
        Extract all URLs from an email, scanning headers (Reply-To, Return-Path, etc.),
        plain text bodies, and HTML bodies.
        """
        if isinstance(eml_content, bytes):
            msg = message_from_bytes(eml_content)
        elif isinstance(eml_content, str):
            msg = message_from_string(eml_content)
        elif isinstance(eml_content, Message):
            msg = eml_content
        else:
            return []

        urls: List[str] = []

        # 1. Extract from headers
        for hdr, val in msg.items():
            if val:
                val_str = str(val)
                fixed_val = re.sub(r'(https?):\s*//', r'\1://', val_str)
                urls.extend(self.extract_urls(fixed_val))

        # 2. Extract from body parts
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type in ["text/plain", "text/html"]:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        text = payload.decode(charset, errors="ignore")
                        if content_type == "text/html":
                            urls.extend(self.extract_urls_from_html(text))
                        else:
                            urls.extend(self.extract_urls(text))
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="ignore")
                if msg.get_content_type() == "text/html":
                    urls.extend(self.extract_urls_from_html(text))
                else:
                    urls.extend(self.extract_urls(text))

        # Deduplicate while preserving ordering
        seen = set()
        deduped = []
        for u in urls:
            cleaned = u.strip()
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                deduped.append(cleaned)
        return deduped

    # --------------------------------------------------------------------------
    # Deterministic Feature Extraction & Baseline Heuristics
    # --------------------------------------------------------------------------
    def _extract_features(self, url: str) -> Dict[str, Any]:
        """Extract deterministic structural and heuristic features from a URL."""
        cleaned_url = url.strip()
        try:
            parsed = urlparse(cleaned_url)
            netloc = parsed.netloc.lower()
            hostname = (parsed.hostname or "").lower()
            path = parsed.path.lower()
            query = parsed.query
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

        has_ip = bool(re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname))
        is_shortened = any(hostname == s or hostname.endswith("." + s) for s in URL_SHORTENERS)
        suspicious_tld = any(hostname.endswith(tld) for tld in KNOWN_SUSPICIOUS_TLDS)
        has_punycode = "xn--" in hostname
        has_at = "@" in netloc or "@" in cleaned_url

        registered_domain, subdomain = get_registered_domain(hostname)
        subdomain_labels = [p for p in subdomain.split(".") if p] if subdomain else []

        brand_findings = check_brand_impersonation(registered_domain, subdomain, TARGET_BRANDS)

        sensitive_keywords = [
            kw for kw in SUSPICIOUS_WORDS
            if re.search(r"\b" + re.escape(kw) + r"\b", path + " " + hostname)
        ]

        return {
            "url": cleaned_url,
            "domain": registered_domain or hostname or "unknown",
            "hostname": hostname,
            "is_malformed": False,
            "has_https": parsed.scheme == "https",
            "has_ip": has_ip,
            "is_shortened": is_shortened,
            "suspicious_tld": suspicious_tld,
            "has_punycode": has_punycode,
            "has_at_symbol": has_at,
            "num_subdomains": len(subdomain_labels),
            "num_hyphens": hostname.count("-"),
            "url_length": len(cleaned_url),
            "num_query_params": len(query.split("&")) if query else 0,
            "has_encoded": "%" in path or "%" in query,
            "brand_findings": brand_findings,
            "sensitive_keywords": sensitive_keywords,
        }

    def _deterministic_analysis(self, url: str, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Fallback deterministic analysis when Grok is unavailable or fails.
        Calculates a score from 0-100 and classifies reputation.
        """
        if features.get("is_malformed"):
            return {
                "url": url,
                "domain": "unknown",
                "registeredAgeDays": -1,
                "reputation": "MALICIOUS",
                "threatScore": 100,
                "flags": ["Malformed or unparseable URL"],
                "redirectChain": [],
                "grok_analysis": None,
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
            flags.append("Uses suspicious/high-abuse top-level domain (+25)")

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
            "registeredAgeDays": -1,
            "reputation": reputation,
            "threatScore": final_score,
            "flags": flags if flags else ["No suspicious patterns detected"],
            "redirectChain": [],
            "grok_analysis": None,
        }

    # --------------------------------------------------------------------------
    # Grok AI Analysis
    # --------------------------------------------------------------------------
    def _build_prompt(self, url: str, features: Dict[str, Any]) -> str:
        """Construct structured prompt for Grok."""
        indicators = []
        if not features["has_https"]:
            indicators.append("No HTTPS (unencrypted plain HTTP)")
        if features["has_ip"]:
            indicators.append(f"Raw IP address host: {features['hostname']}")
        if features["has_punycode"]:
            indicators.append("Punycode/homograph domain")
        if features["is_shortened"]:
            indicators.append("URL shortener service")
        if features["suspicious_tld"]:
            indicators.append("Suspicious / abuse-prone TLD")
        if features["brand_findings"]:
            indicators.append(f"Brand impersonation cues: {'; '.join(features['brand_findings'])}")
        if features["sensitive_keywords"]:
            indicators.append(f"Sensitive keywords: {', '.join(features['sensitive_keywords'])}")
        if features["num_query_params"] > 5:
            indicators.append(f"Multiple query parameters: {features['num_query_params']}")

        indicators_str = "\n".join(f"- {ind}" for ind in indicators) if indicators else "- No heuristic anomalies detected"

        return f"""Analyze this URL for phishing, credential harvesting, malware delivery, or benign intent:

URL: {url}
Domain: {features['domain']}
Technical Indicators:
{indicators_str}

Respond with your evaluation in this EXACT format:
VERDICT: [BENIGN, PHISHING, MALICIOUS, or SUSPICIOUS]
CONFIDENCE: [0.0 to 1.0 or 0 to 100%]
REASON: [1-2 sentences explaining your technical reasoning]
FLAGS: [comma-separated security flags or 'None']"""

    def _grok_analyze(self, url: str, features: Dict[str, Any]) -> Dict[str, Any]:
        """Invoke Grok API via OpenAI-compatible client."""
        prompt = self._build_prompt(url, features)

        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are an elite cybersecurity specialist and automated email threat forensics analyst. "
                        "Evaluate URLs strictly into one of: BENIGN, PHISHING, MALICIOUS, SUSPICIOUS. "
                        "Provide a realistic confidence score and clear, concise reasoning."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            max_tokens=250,
        )

        content = response.choices[0].message.content or ""
        return self._parse_grok_response(content)

    def _parse_grok_response(self, response_text: str) -> Dict[str, Any]:
        """Parse Grok's text output into a structured dictionary."""
        result = {
            "verdict": "UNKNOWN",
            "confidence": 0.5,
            "reason": "Grok response received",
            "flags": [],
        }

        # Try JSON parsing first if the model wrapped output in JSON
        json_match = re.search(r"\{[\s\S]*\}", response_text)
        if json_match:
            try:
                parsed_json = json.loads(json_match.group(0))
                verdict = str(parsed_json.get("verdict", "")).strip().upper()
                if verdict in ["BENIGN", "PHISHING", "MALICIOUS", "SUSPICIOUS"]:
                    result["verdict"] = verdict
                
                raw_conf = parsed_json.get("confidence", 0.5)
                try:
                    conf = float(raw_conf)
                    if conf > 1.0:
                        conf = conf / 100.0
                    result["confidence"] = max(0.0, min(conf, 1.0))
                except Exception:
                    pass

                if "reason" in parsed_json:
                    result["reason"] = str(parsed_json["reason"]).strip()
                if "flags" in parsed_json:
                    flags_val = parsed_json["flags"]
                    if isinstance(flags_val, list):
                        result["flags"] = [str(f).strip() for f in flags_val if str(f).strip().lower() != "none"]
                    elif isinstance(flags_val, str) and flags_val.lower() != "none":
                        result["flags"] = [f.strip() for f in flags_val.split(",") if f.strip()]
                return result
            except Exception:
                pass

        # Parse key-value lines
        lines = response_text.strip().split("\n")
        for line in lines:
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
                cleaned_flags = value.strip("[]\"' ")
                if cleaned_flags.lower() not in ["none", "n/a", "no flags"]:
                    result["flags"] = [f.strip() for f in cleaned_flags.split(",") if f.strip()]

        return result

    # --------------------------------------------------------------------------
    # Merging Grok AI Results with Deterministic Features
    # --------------------------------------------------------------------------
    def _merge_results(
        self,
        url: str,
        features: Dict[str, Any],
        deterministic: Dict[str, Any],
        grok_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Merge Grok AI verdict, confidence, and reasoning with deterministic features,
        calibrating a holistic threat score (0-100) and authoritative reputation.
        """
        verdict = grok_result.get("verdict", "UNKNOWN")
        confidence = float(grok_result.get("confidence", 0.5))
        reason = grok_result.get("reason", "Analysis completed by Grok AI")
        det_score = deterministic["threatScore"]

        # Map verdict to reputation strictly within {"MALICIOUS", "SUSPICIOUS", "SAFE", "UNKNOWN"}
        if verdict in ["MALICIOUS", "PHISHING"]:
            reputation = "MALICIOUS"
        elif verdict == "SUSPICIOUS":
            reputation = "SUSPICIOUS"
        elif verdict == "BENIGN":
            # Safety floor: if deterministic indicators are critically high (e.g. raw IP host or severe spoofing),
            # don't completely mark SAFE; mark SUSPICIOUS
            if det_score >= 60:
                reputation = "SUSPICIOUS"
            else:
                reputation = "SAFE"
        else:
            reputation = deterministic["reputation"]

        # Calibrate threat score (0-100)
        ai_base_score = 0
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

        # Blended threat score: 45% deterministic heuristics, 55% Grok intelligence
        if verdict in ["MALICIOUS", "PHISHING"]:
            merged_score = max(det_score, int(0.40 * det_score + 0.60 * ai_base_score))
        elif verdict == "BENIGN":
            if det_score >= 60:
                # Disagreement: high deterministic risk vs benign AI verdict
                merged_score = int(0.60 * det_score + 0.40 * ai_base_score)
            else:
                merged_score = min(det_score, int(0.45 * det_score + 0.55 * ai_base_score))
        else:
            merged_score = int(0.50 * det_score + 0.50 * ai_base_score)

        final_threat_score = max(0, min(merged_score, 100))

        # Merge flags preserving order and deduplicating
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
            "grok_analysis": {
                "verdict": verdict,
                "confidence": round(confidence, 2),
                "reason": reason,
            },
        }

    # --------------------------------------------------------------------------
    # Public Analysis Methods
    # --------------------------------------------------------------------------
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze a single URL using Grok AI if enabled/available, with seamless
        fallback to deterministic heuristic analysis.
        """
        features = self._extract_features(url)
        deterministic = self._deterministic_analysis(url, features)

        if not self.enabled or not self.client:
            return deterministic

        try:
            grok_result = self._grok_analyze(url, features)
            return self._merge_results(url, features, deterministic, grok_result)
        except Exception as e:
            logger.warning(f"Grok analysis failed for URL '{url}': {e}. Falling back to deterministic results.")
            return deterministic

    def analyze_urls(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Analyze a collection of URLs."""
        return [self.analyze_url(u) for u in urls]

    def analyze_email(self, eml_content: Union[str, bytes, Message]) -> Dict[str, Any]:
        """
        Extract and analyze all URLs found in an email message.
        Returns a summary dictionary with individual URL analyses and risk assessment.
        """
        extracted = self.extract_urls_from_email(eml_content)
        if not extracted:
            return {
                "urls_found": [],
                "analyzed_urls": [],
                "total_urls": 0,
                "max_threat_score": 0,
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