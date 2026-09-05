"""
DNS Threat Intelligence Module
Resolves domain DNS records (MX, A, TXT/SPF, DMARC, NS) and inspects DNSBL listings
using dnspython with bounded timeouts and offline safety.
"""

import ipaddress
import logging
from typing import Optional, List, Tuple
import dns.resolver
import dns.exception

from ..config import (
    ENABLE_DNSBL,
    REQUEST_TIMEOUT_SECONDS,
    CACHE_TTL_SECONDS,
    MAX_CACHE_ENTRIES,
)
from .models import DNSIntelligenceResult, ProvenanceType
from .caching import TTLCache
from .domain_intelligence import to_punycode
from ..analyzers.origin_analysis import classify_ip_type

logger = logging.getLogger(__name__)

DEFAULT_DNSBL_ZONES = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
]


class DNSIntelligenceService:
    """
    DNS Intelligence Service providing DNS record resolution and DNSBL inspection.
    """

    def __init__(
        self,
        enabled: bool = True,
        dnsbl_enabled: bool = ENABLE_DNSBL,
        timeout: float = min(REQUEST_TIMEOUT_SECONDS, 2.0),
        dnsbl_zones: Optional[List[str]] = None,
        cache: Optional[TTLCache] = None,
    ):
        self.enabled = enabled
        self.dnsbl_enabled = dnsbl_enabled
        self.timeout = timeout
        self.dnsbl_zones = dnsbl_zones or list(DEFAULT_DNSBL_ZONES)
        self.cache = cache or TTLCache(maxsize=MAX_CACHE_ENTRIES, default_ttl=CACHE_TTL_SECONDS)

        # Configure resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = self.timeout
        self.resolver.timeout = self.timeout

    def resolve_domain(self, domain: str) -> DNSIntelligenceResult:
        if not domain or "." not in domain:
            return DNSIntelligenceResult(
                domain=domain or "",
                provenance=ProvenanceType.NOT_CHECKED,
                error="Invalid domain name",
            )

        punycode = to_punycode(domain)

        # Check Cache
        cached = self.cache.get(f"dns:{punycode}")
        if cached is not None:
            return cached

        if not self.enabled:
            result = DNSIntelligenceResult(
                domain=domain,
                provenance=ProvenanceType.NOT_CHECKED,
            )
            self.cache.set(f"dns:{punycode}", result)
            return result

        mx_records: List[str] = []
        a_records: List[str] = []
        txt_records: List[str] = []
        ns_records: List[str] = []
        spf_record: Optional[str] = None
        dmarc_record: Optional[str] = None
        has_verified_data = False
        error_msg = None

        # 1. Resolve MX
        try:
            answers = self.resolver.resolve(punycode, "MX")
            mx_records = [str(r.exchange).rstrip(".") for r in answers]
            has_verified_data = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as e:
            logger.debug(f"DNS MX lookup error for {punycode}: {e}")

        # 2. Resolve A
        try:
            answers = self.resolver.resolve(punycode, "A")
            a_records = [str(r) for r in answers]
            has_verified_data = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as e:
            logger.debug(f"DNS A lookup error for {punycode}: {e}")

        # 3. Resolve NS
        try:
            answers = self.resolver.resolve(punycode, "NS")
            ns_records = [str(r.target).rstrip(".") for r in answers]
            has_verified_data = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as e:
            logger.debug(f"DNS NS lookup error for {punycode}: {e}")

        # 4. Resolve TXT (find SPF)
        try:
            answers = self.resolver.resolve(punycode, "TXT")
            for r in answers:
                # r.strings is tuple of bytes
                txt_str = b"".join(r.strings).decode("utf-8", errors="replace")
                txt_records.append(txt_str)
                if txt_str.lower().startswith("v=spf1"):
                    spf_record = txt_str
            has_verified_data = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as e:
            logger.debug(f"DNS TXT lookup error for {punycode}: {e}")

        # 5. Resolve DMARC (_dmarc.<punycode>)
        try:
            dmarc_host = f"_dmarc.{punycode}"
            answers = self.resolver.resolve(dmarc_host, "TXT")
            for r in answers:
                txt_str = b"".join(r.strings).decode("utf-8", errors="replace")
                if txt_str.lower().startswith("v=dmarc1"):
                    dmarc_record = txt_str
                    break
            has_verified_data = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as e:
            logger.debug(f"DNS DMARC lookup error for {punycode}: {e}")

        provenance = ProvenanceType.VERIFIED if has_verified_data else ProvenanceType.UNAVAILABLE

        result = DNSIntelligenceResult(
            domain=domain,
            mx_records=mx_records,
            a_records=a_records,
            txt_records=txt_records,
            ns_records=ns_records,
            spf_record=spf_record,
            dmarc_record=dmarc_record,
            dnsbl_listed=False,
            dnsbl_matches=[],
            provenance=provenance,
            error=error_msg,
        )

        self.cache.set(f"dns:{punycode}", result)
        return result

    def check_dnsbl(self, ip_str: str) -> Tuple[bool, List[str]]:
        """
        Query DNSBL zones for a given IP address.
        Guarantees private / non-routable IPs are never queried.
        Returns: (is_listed, list_of_matching_zones)
        """
        if not self.dnsbl_enabled or not ip_str:
            return False, []

        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return False, []

        # Only global IPv4 addresses are standard for DNSBL queries
        if ip_obj.version != 4 or classify_ip_type(ip_obj) != "global":
            return False, []

        # Invert IPv4 octets (1.2.3.4 -> 4.3.2.1)
        octets = ip_str.strip().split(".")
        reversed_ip = ".".join(reversed(octets))

        matches = []
        for zone in self.dnsbl_zones:
            query_host = f"{reversed_ip}.{zone}"
            try:
                answers = self.resolver.resolve(query_host, "A")
                if answers:
                    matches.append(zone)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                # Clean / unlisted
                pass
            except Exception as e:
                logger.debug(f"DNSBL query failed for {query_host}: {e}")

        return bool(matches), matches
