"""
SSRF-Safe URL Redirect Analyzer Module
Performs recursive redirect tracing with pre-flight DNS address validation to strictly
prevent Server-Side Request Forgery (SSRF) against internal networks and metadata services.
"""

import socket
import logging
import urllib.parse
import ipaddress
from typing import Optional, List, Tuple, Dict, Any
import requests

from ..config import (
    REQUEST_TIMEOUT_SECONDS,
    MAX_REDIRECTS,
    MAX_REDIRECT_BYTES,
)
from .models import RedirectAnalysisResult, ProvenanceType
from ..analyzers.origin_analysis import classify_ip_type

logger = logging.getLogger(__name__)


def is_ip_restricted(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Tuple[bool, str]:
    """
    Strict validation that an IP address is publicly routable on the global Internet.
    Blocks loopback (127.x, ::1), private (RFC1918, ULA), link-local (169.254.x metadata),
    multicast, reserved, and documentation ranges.
    """
    if ip_obj.is_loopback:
        return True, f"Loopback address ({ip_obj})"
    if ip_obj.is_link_local:
        return True, f"Link-local / Cloud Metadata address ({ip_obj})"
    if ip_obj.is_private:
        return True, f"Private RFC 1918 / ULA address ({ip_obj})"
    if ip_obj.is_multicast:
        return True, f"Multicast address ({ip_obj})"
    if ip_obj.is_reserved:
        return True, f"Reserved address ({ip_obj})"
    if not ip_obj.is_global:
        return True, f"Non-global / Documentation address ({ip_obj})"
    if str(ip_obj) in ("0.0.0.0", "::"):
        return True, f"Unspecified zero address ({ip_obj})"
    return False, ""


def check_url_ssrf_safety(url: str) -> Tuple[bool, Optional[str], bool]:
    """
    Pre-flight DNS validation for URL before establishing an HTTP connection.
    Resolves hostname to IP addresses and rejects if ANY IP is restricted.
    Returns: (is_safe, reason, is_ssrf_restriction)
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as e:
        return False, f"Invalid URL syntax: {e}", False

    if parsed.scheme not in ("http", "https"):
        return False, f"Prohibited URL scheme '{parsed.scheme}'; only http/https permitted", False

    hostname = parsed.hostname
    if not hostname:
        return False, "URL missing valid hostname", False

    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # 1. Check if hostname is an IP literal
    try:
        ip_obj = ipaddress.ip_address(hostname.strip("[]"))
        restricted, reason = is_ip_restricted(ip_obj)
        if restricted:
            return False, f"Target IP is restricted: {reason}", True
        return True, None, False
    except ValueError:
        pass  # Hostname is a domain name, proceed to DNS resolution

    # 2. Resolve domain name to all candidate IPs
    try:
        addr_info = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
        if not addr_info:
            return False, f"DNS resolution yielded no address records for host '{hostname}'", False

        for entry in addr_info:
            sockaddr = entry[4]
            ip_str = sockaddr[0]
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                restricted, reason = is_ip_restricted(ip_obj)
                if restricted:
                    return False, f"Host '{hostname}' resolved to restricted IP: {reason}", True
            except ValueError:
                return False, f"Failed to parse resolved IP '{ip_str}' for host '{hostname}'", False

        return True, None, False
    except socket.gaierror as e:
        return False, f"DNS resolution failed for host '{hostname}': {e}", False
    except Exception as e:
        return False, f"Pre-flight check failed for host '{hostname}': {e}", False


class RedirectAnalyzer:
    """
    Bounded, SSRF-safe URL redirect analyzer.
    Follows HTTP redirects step-by-step, validating every hop's destination IP before connection.
    """

    def __init__(
        self,
        max_redirects: int = MAX_REDIRECTS,
        timeout: float = REQUEST_TIMEOUT_SECONDS,
        max_bytes: int = MAX_REDIRECT_BYTES,
    ):
        self.max_redirects = max_redirects
        self.timeout = timeout
        self.max_bytes = max_bytes

    def trace_redirects(self, initial_url: str) -> RedirectAnalysisResult:
        if not initial_url:
            return RedirectAnalysisResult(
                initial_url="",
                final_url="",
                provenance=ProvenanceType.NOT_CHECKED,
            )

        current_url = initial_url
        chain = [current_url]
        hop_count = 0
        is_blocked = False
        blocked_reason = None
        error_msg = None

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        while hop_count < self.max_redirects:
            # 1. Pre-flight SSRF Validation
            safe, check_reason, is_ssrf = check_url_ssrf_safety(current_url)
            if not safe:
                if is_ssrf:
                    is_blocked = True
                    blocked_reason = check_reason
                    logger.warning(f"SSRF protection blocked URL '{current_url}': {check_reason}")
                else:
                    error_msg = check_reason
                break

            # 2. Request single hop (do not follow redirects automatically)
            try:
                resp = requests.get(
                    current_url,
                    headers=headers,
                    allow_redirects=False,
                    timeout=self.timeout,
                    stream=True,
                )
                # Consume max bytes and close immediately
                try:
                    resp.raw.read(self.max_bytes)
                finally:
                    resp.close()

                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location")
                    if not location:
                        break  # Redirect status but no Location header
                    next_url = urllib.parse.urljoin(current_url, location)
                    if next_url in chain:
                        # Redirect loop detected
                        break
                    chain.append(next_url)
                    current_url = next_url
                    hop_count += 1
                else:
                    # Final destination reached
                    break
            except Exception as e:
                logger.debug(f"Redirect check failed at hop {hop_count} ({current_url}): {e}")
                break

        # Check for domain change / disguised domain
        init_domain = urllib.parse.urlparse(initial_url).hostname or ""
        final_domain = urllib.parse.urlparse(current_url).hostname or ""
        is_disguised = bool(init_domain and final_domain and init_domain.lower() != final_domain.lower())

        provenance = ProvenanceType.VERIFIED if not is_blocked else ProvenanceType.OBSERVED

        return RedirectAnalysisResult(
            initial_url=initial_url,
            final_url=current_url,
            redirect_chain=chain,
            hop_count=hop_count,
            is_ssrf_blocked=is_blocked,
            blocked_reason=blocked_reason,
            is_disguised_domain=is_disguised,
            provenance=provenance,
        )
