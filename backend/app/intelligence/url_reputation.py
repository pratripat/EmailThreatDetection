"""
URL Threat Intelligence Module
Integrates external URL reputation APIs (VirusTotal URL, URLhaus) with caching,
bounded timeouts, and offline-safe fallbacks.
"""

import base64
import logging
from typing import Optional, Dict, Any
import requests

from ..config import (
    VIRUSTOTAL_API_KEY,
    URLHAUS_API_KEY,
    REQUEST_TIMEOUT_SECONDS,
    CACHE_TTL_SECONDS,
    MAX_CACHE_ENTRIES,
)
from .models import URLReputationResult, ProvenanceType
from .caching import TTLCache
from ..analyzers.url_analysis import analyze_url

logger = logging.getLogger(__name__)


def url_to_vt_id(url: str) -> str:
    """Encode URL as unpadded base64 string for VirusTotal API v3."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


class URLReputationService:
    """
    Composite URL Threat Reputation Service.
    Queries VirusTotal and URLhaus (if keys/configured) with strict caching and timeouts.
    """

    def __init__(
        self,
        virustotal_key: Optional[str] = None,
        timeout: float = REQUEST_TIMEOUT_SECONDS,
        cache: Optional[TTLCache] = None,
    ):
        self.virustotal_key = (virustotal_key or VIRUSTOTAL_API_KEY).strip()
        self.timeout = timeout
        self.cache = cache or TTLCache(maxsize=MAX_CACHE_ENTRIES, default_ttl=CACHE_TTL_SECONDS)

    def lookup(self, url: str) -> URLReputationResult:
        if not url:
            return URLReputationResult(
                url="",
                domain="",
                provenance=ProvenanceType.NOT_CHECKED,
            )

        # Baseline heuristic parsing
        base_res = analyze_url(url)
        domain = base_res.get("domain", "")

        # Check Cache
        cached = self.cache.get(url)
        if cached is not None:
            return cached

        # If no external API key, return offline heuristic result
        if not self.virustotal_key:
            heuristic_threat_score = base_res.get("threatScore", 0)
            is_heuristic_malicious = base_res.get("reputation") == "MALICIOUS"
            result = URLReputationResult(
                url=url,
                domain=domain,
                is_malicious=is_heuristic_malicious,
                threat_score=heuristic_threat_score,
                engine_detections=0,
                total_engines=0,
                categories=base_res.get("flags", []),
                provenance=ProvenanceType.HEURISTIC if heuristic_threat_score > 0 else ProvenanceType.NOT_CHECKED,
                source="local_heuristics",
            )
            self.cache.set(url, result)
            return result

        # Query VirusTotal URL API v3
        vt_id = url_to_vt_id(url)
        vt_url = f"https://www.virustotal.com/api/v3/urls/{vt_id}"
        headers = {
            "x-apikey": self.virustotal_key,
            "User-Agent": "EmailThreatForensics/3.0",
        }

        try:
            resp = requests.get(vt_url, headers=headers, timeout=self.timeout)
            if resp.status_code == 200:
                attr = resp.json().get("data", {}).get("attributes", {})
                stats = attr.get("last_analysis_stats", {})
                malicious = int(stats.get("malicious", 0))
                suspicious = int(stats.get("suspicious", 0))
                harmless = int(stats.get("harmless", 0))
                undetected = int(stats.get("undetected", 0))
                total = malicious + suspicious + harmless + undetected

                categories = list(attr.get("categories", {}).values())

                threat_score = min(100, (malicious * 25) + (suspicious * 10))
                is_malicious = malicious >= 2 or threat_score >= 70

                result = URLReputationResult(
                    url=url,
                    domain=domain,
                    is_malicious=is_malicious,
                    threat_score=threat_score,
                    engine_detections=malicious,
                    total_engines=total,
                    categories=categories,
                    provenance=ProvenanceType.VERIFIED,
                    source="virustotal",
                )
            elif resp.status_code == 404:
                # URL not seen in VirusTotal
                result = URLReputationResult(
                    url=url,
                    domain=domain,
                    is_malicious=False,
                    threat_score=0,
                    engine_detections=0,
                    total_engines=0,
                    provenance=ProvenanceType.VERIFIED,
                    source="virustotal_unseen",
                )
            else:
                result = URLReputationResult(
                    url=url,
                    domain=domain,
                    is_malicious=False,
                    threat_score=base_res.get("threatScore", 0),
                    provenance=ProvenanceType.UNAVAILABLE,
                    source=f"virustotal_http_{resp.status_code}",
                    error=f"VirusTotal returned status {resp.status_code}",
                )
        except Exception as e:
            logger.debug(f"VirusTotal lookup failed for {url}: {e}")
            result = URLReputationResult(
                url=url,
                domain=domain,
                is_malicious=False,
                threat_score=base_res.get("threatScore", 0),
                provenance=ProvenanceType.UNAVAILABLE,
                source="virustotal_error",
                error=str(e),
            )

        self.cache.set(url, result)
        return result
