"""
IP Threat Intelligence Module
Provides bounded, cached, and offline-safe IP reputation lookups.
Integrates local origin analysis with external providers (AbuseIPDB, VirusTotal).
Strictly prevents querying non-routable, private, loopback, or documentation addresses.
"""

import ipaddress
import logging
from typing import Optional, Dict, Any
import requests

from ..config import (
    ABUSEIPDB_API_KEY,
    VIRUSTOTAL_API_KEY,
    REQUEST_TIMEOUT_SECONDS,
    CACHE_TTL_SECONDS,
    MAX_CACHE_ENTRIES,
)
from .models import IPIntelligenceResult, ProvenanceType
from .caching import TTLCache
from ..analyzers.origin_analysis import OriginAnalyzer, classify_ip_type

logger = logging.getLogger(__name__)


class BaseIPReputationProvider:
    """Abstract interface for external IP threat intelligence providers."""
    def lookup(self, ip: str, timeout: float) -> Optional[Dict[str, Any]]:
        raise NotImplementedError


class AbuseIPDBProvider(BaseIPReputationProvider):
    """AbuseIPDB IP Check Provider v2."""
    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str):
        self.api_key = api_key.strip()

    def lookup(self, ip: str, timeout: float = 3.0) -> Optional[Dict[str, Any]]:
        if not self.api_key:
            return None
        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
            "User-Agent": "EmailThreatForensics/3.0",
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": True,
        }
        try:
            resp = requests.get(self.BASE_URL, headers=headers, params=params, timeout=timeout)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                return {
                    "abuse_score": int(data.get("abuseConfidenceScore", 0)),
                    "is_whitelisted": bool(data.get("isWhitelisted", False)),
                    "total_reports": int(data.get("totalReports", 0)),
                    "country_code": data.get("countryCode") or "UNKNOWN",
                    "country_name": data.get("countryName"),
                    "isp": data.get("isp") or "UNKNOWN",
                    "domain": data.get("domain"),
                }
            else:
                logger.warning(f"AbuseIPDB query for {ip} returned status {resp.status_code}")
                return None
        except Exception as e:
            logger.debug(f"AbuseIPDB query failed for {ip}: {e}")
            return None


class VirusTotalIPProvider(BaseIPReputationProvider):
    """VirusTotal IP Address Report API v3."""
    BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses"

    def __init__(self, api_key: str):
        self.api_key = api_key.strip()

    def lookup(self, ip: str, timeout: float = 3.0) -> Optional[Dict[str, Any]]:
        if not self.api_key:
            return None
        headers = {
            "x-apikey": self.api_key,
            "User-Agent": "EmailThreatForensics/3.0",
        }
        try:
            url = f"{self.BASE_URL}/{ip}"
            resp = requests.get(url, headers=headers, timeout=timeout)
            if resp.status_code == 200:
                attr = resp.json().get("data", {}).get("attributes", {})
                stats = attr.get("last_analysis_stats", {})
                malicious = int(stats.get("malicious", 0))
                suspicious = int(stats.get("suspicious", 0))
                total = malicious + suspicious + int(stats.get("harmless", 0)) + int(stats.get("undetected", 0))
                ratio_str = f"{malicious}/{total}" if total > 0 else "0/0"
                return {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "ratio": ratio_str,
                    "asn": str(attr.get("asn", "UNKNOWN")),
                    "as_owner": attr.get("as_owner") or "UNKNOWN",
                    "country": attr.get("country") or "UNKNOWN",
                }
            else:
                logger.warning(f"VirusTotal IP query for {ip} returned status {resp.status_code}")
                return None
        except Exception as e:
            logger.debug(f"VirusTotal IP query failed for {ip}: {e}")
            return None


class IPReputationService:
    """
    Composite IP Threat Intelligence Service.
    Integrates local subnet/VPN/datacenter classification with external threat feeds.
    """

    def __init__(
        self,
        origin_analyzer: Optional[OriginAnalyzer] = None,
        abuseipdb_key: Optional[str] = None,
        virustotal_key: Optional[str] = None,
        timeout: float = REQUEST_TIMEOUT_SECONDS,
        cache: Optional[TTLCache] = None,
    ):
        self.origin_analyzer = origin_analyzer
        self.abuseipdb_provider = AbuseIPDBProvider(abuseipdb_key or ABUSEIPDB_API_KEY)
        self.virustotal_provider = VirusTotalIPProvider(virustotal_key or VIRUSTOTAL_API_KEY)
        self.timeout = timeout
        self.cache = cache or TTLCache(maxsize=MAX_CACHE_ENTRIES, default_ttl=CACHE_TTL_SECONDS)

    def lookup(self, ip_str: str) -> IPIntelligenceResult:
        if not ip_str or ip_str in ("0.0.0.0", "::"):
            return IPIntelligenceResult(
                ip=ip_str or "0.0.0.0",
                is_non_routable=True,
                non_routable_reason="unspecified_address",
                reputation="UNKNOWN",
                abuse_category="NOT_CHECKED",
                provenance=ProvenanceType.NOT_CHECKED,
            )

        # 1. Parse and validate IP
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return IPIntelligenceResult(
                ip=ip_str,
                is_non_routable=True,
                non_routable_reason="invalid_ip_format",
                reputation="UNKNOWN",
                abuse_category="NOT_CHECKED",
                provenance=ProvenanceType.OBSERVED,
                error="Invalid IP address format",
            )

        # 2. Check routability - strictly skip non-routable IPs from external queries
        ip_category = classify_ip_type(ip_obj)
        if ip_category != "global":
            return IPIntelligenceResult(
                ip=ip_str,
                is_non_routable=True,
                non_routable_reason=f"non_global_{ip_category}",
                country_code="LOCAL",
                country_name="Internal / Non-Routable Network",
                isp="Private Network",
                reputation="UNKNOWN",
                abuse_category="NOT_CHECKED",
                virus_total_ratio="NOT_QUERIED",
                provenance=ProvenanceType.OBSERVED,
                source="local_rfc_classification",
            )

        # 3. Check Cache
        cached = self.cache.get(ip_str)
        if cached is not None:
            return cached

        # 4. Local Origin Analysis (VPN / Datacenter lists)
        is_vpn = False
        is_datacenter = False
        if self.origin_analyzer:
            try:
                assessment = self.origin_analyzer.assess(ip_str)
                is_vpn = assessment.is_vpn
                is_datacenter = assessment.is_datacenter
            except Exception:
                pass

        # 5. External Intelligence Queries (if configured)
        abuse_data = self.abuseipdb_provider.lookup(ip_str, timeout=self.timeout)
        vt_data = self.virustotal_provider.lookup(ip_str, timeout=self.timeout)

        abuse_score = 0
        is_whitelisted = False
        total_reports = 0
        country_code = "UNKNOWN"
        country_name = None
        city = None
        asn = "UNKNOWN"
        isp = "UNKNOWN"
        domain = None
        vt_ratio = "NOT_QUERIED"
        has_external_data = False

        if abuse_data:
            has_external_data = True
            abuse_score = abuse_data["abuse_score"]
            is_whitelisted = abuse_data["is_whitelisted"]
            total_reports = abuse_data["total_reports"]
            country_code = abuse_data["country_code"]
            country_name = abuse_data["country_name"]
            isp = abuse_data["isp"]
            domain = abuse_data["domain"]

        if vt_data:
            has_external_data = True
            vt_ratio = vt_data["ratio"]
            if vt_data.get("asn") and vt_data["asn"] != "UNKNOWN":
                asn = vt_data["asn"]
            if vt_data.get("as_owner") and vt_data["as_owner"] != "UNKNOWN":
                isp = vt_data["as_owner"]
            if country_code == "UNKNOWN" and vt_data.get("country") != "UNKNOWN":
                country_code = vt_data["country"]

        # 6. Reputation & Provenance Determination
        if has_external_data:
            provenance = ProvenanceType.VERIFIED
            vt_malicious = vt_data.get("malicious", 0) if vt_data else 0

            if abuse_score >= 80 or vt_malicious >= 3:
                reputation = "MALICIOUS"
                abuse_category = "HIGH RISK"
            elif abuse_score >= 20 or vt_malicious >= 1 or is_vpn or is_datacenter:
                reputation = "SUSPICIOUS"
                abuse_category = "MEDIUM RISK"
            elif abuse_score < 20 and vt_malicious == 0:
                reputation = "CLEAN"
                abuse_category = "CLEAN"
            else:
                reputation = "UNKNOWN"
                abuse_category = "NOT_CHECKED"
            source = "external_intel"
        else:
            # Offline or unconfigured
            if is_vpn or is_datacenter:
                reputation = "SUSPICIOUS"
                abuse_category = "MEDIUM RISK"
                provenance = ProvenanceType.HEURISTIC
                source = "local_origin_lists"
            else:
                reputation = "UNKNOWN"
                abuse_category = "NOT_CHECKED"
                provenance = ProvenanceType.NOT_CHECKED
                source = "offline_default"

        result = IPIntelligenceResult(
            ip=ip_str,
            abuse_score=abuse_score,
            is_whitelisted=is_whitelisted,
            total_reports=total_reports,
            is_vpn=is_vpn,
            is_datacenter=is_datacenter,
            is_non_routable=False,
            country_code=country_code,
            country_name=country_name,
            city=city,
            asn=asn,
            isp=isp,
            domain=domain,
            reputation=reputation,
            abuse_category=abuse_category,
            virus_total_ratio=vt_ratio,
            spamhaus_listed=False,
            provenance=provenance,
            source=source,
        )

        self.cache.set(ip_str, result)
        return result
