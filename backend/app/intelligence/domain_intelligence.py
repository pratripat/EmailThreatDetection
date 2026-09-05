"""
Domain Threat Intelligence Module
Performs IDN Punycode normalization and bounded RDAP (Registration Data Access Protocol)
lookups for domain age and registrar intelligence without blocking offline operations.
"""

import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any
import requests

from ..config import (
    ENABLE_RDAP,
    REQUEST_TIMEOUT_SECONDS,
    CACHE_TTL_SECONDS,
    MAX_CACHE_ENTRIES,
)
from .models import DomainIntelligenceResult, ProvenanceType
from .caching import TTLCache

logger = logging.getLogger(__name__)


def to_punycode(domain: str) -> str:
    """Normalize internationalized domain name (IDN) to ASCII Punycode."""
    if not domain:
        return ""
    try:
        return domain.strip().lower().encode("idna").decode("ascii")
    except Exception:
        return domain.strip().lower()


class DomainIntelligenceService:
    """
    Domain Intelligence Service querying public RDAP endpoints.
    Provides verified domain registration dates and age calculations.
    """
    RDAP_BASE_URL = "https://rdap.org/domain"

    def __init__(
        self,
        enabled: bool = ENABLE_RDAP,
        timeout: float = REQUEST_TIMEOUT_SECONDS,
        cache: Optional[TTLCache] = None,
    ):
        self.enabled = enabled
        self.timeout = timeout
        self.cache = cache or TTLCache(maxsize=MAX_CACHE_ENTRIES, default_ttl=CACHE_TTL_SECONDS)

    def lookup(self, domain: str) -> DomainIntelligenceResult:
        if not domain or "." not in domain:
            return DomainIntelligenceResult(
                domain=domain or "",
                punycode=domain or "",
                registered_age_days=-1,
                provenance=ProvenanceType.NOT_CHECKED,
                source="invalid_domain",
            )

        punycode = to_punycode(domain)

        # Check Cache
        cached = self.cache.get(punycode)
        if cached is not None:
            return cached

        if not self.enabled:
            result = DomainIntelligenceResult(
                domain=domain,
                punycode=punycode,
                registered_age_days=-1,
                provenance=ProvenanceType.NOT_CHECKED,
                source="rdap_disabled",
            )
            self.cache.set(punycode, result)
            return result

        # Query RDAP
        url = f"{self.RDAP_BASE_URL}/{punycode}"
        headers = {
            "Accept": "application/rdap+json, application/json",
            "User-Agent": "EmailThreatForensics/3.0",
        }

        try:
            resp = requests.get(url, headers=headers, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                created_str = None
                # RDAP events array contains registration timestamp
                events = data.get("events", [])
                for ev in events:
                    action = ev.get("eventAction", "").lower()
                    if action in ("registration", "created"):
                        created_str = ev.get("eventDate")
                        break

                registered_age_days = -1
                is_newly_registered = False
                if created_str:
                    try:
                        # Clean trailing Z for fromisoformat compatibility in 3.10/3.11
                        iso_clean = created_str.replace("Z", "+00:00")
                        created_dt = datetime.fromisoformat(iso_clean)
                        now_dt = datetime.now(timezone.utc)
                        delta = now_dt - created_dt
                        registered_age_days = max(0, delta.days)
                        if 0 <= registered_age_days < 30:
                            is_newly_registered = True
                    except Exception as parse_err:
                        logger.debug(f"Failed to parse RDAP eventDate '{created_str}': {parse_err}")

                # Extract registrar name
                registrar_name = None
                for entity in data.get("entities", []):
                    roles = [r.lower() for r in entity.get("roles", [])]
                    if "registrar" in roles:
                        vcard = entity.get("vcardArray", [])
                        if len(vcard) > 1:
                            for prop in vcard[1]:
                                if len(prop) > 3 and prop[0] == "fn":
                                    registrar_name = prop[3]
                                    break
                    if registrar_name:
                        break

                result = DomainIntelligenceResult(
                    domain=domain,
                    punycode=punycode,
                    registered_age_days=registered_age_days,
                    creation_date=created_str,
                    registrar=registrar_name,
                    is_newly_registered=is_newly_registered,
                    provenance=ProvenanceType.VERIFIED,
                    source="rdap_org",
                )
            elif resp.status_code == 404:
                result = DomainIntelligenceResult(
                    domain=domain,
                    punycode=punycode,
                    registered_age_days=-1,
                    provenance=ProvenanceType.VERIFIED,
                    source="rdap_404_not_found",
                    error="Domain not found in RDAP registry",
                )
            else:
                result = DomainIntelligenceResult(
                    domain=domain,
                    punycode=punycode,
                    registered_age_days=-1,
                    provenance=ProvenanceType.UNAVAILABLE,
                    source=f"rdap_http_{resp.status_code}",
                    error=f"RDAP returned status {resp.status_code}",
                )
        except Exception as e:
            logger.debug(f"RDAP lookup failed for {domain}: {e}")
            result = DomainIntelligenceResult(
                domain=domain,
                punycode=punycode,
                registered_age_days=-1,
                provenance=ProvenanceType.UNAVAILABLE,
                source="rdap_error",
                error=str(e),
            )

        self.cache.set(punycode, result)
        return result
