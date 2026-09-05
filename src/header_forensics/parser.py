"""
Header & Relay Path Parser
Parses RFC 5322 Received headers, extracts relay hops, and isolates IPv4/IPv6 candidates.
"""

import re
import ipaddress
from dataclasses import dataclass
from typing import Optional, List

IPV4_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


@dataclass
class RelayHop:
    raw: str
    from_host: Optional[str] = None
    by_host: Optional[str] = None
    with_protocol: Optional[str] = None
    timestamp: Optional[str] = None


def parse_received_header(raw_header: str) -> RelayHop:
    """Extract from/by/with/timestamp from a single Received: header."""
    hop = RelayHop(raw=raw_header)

    from_match = re.search(r'from\s+(.*?)\s+(?:by|with|id|via|for|;|\r?\n|$)', raw_header, re.DOTALL | re.IGNORECASE)
    if from_match:
        hop.from_host = ' '.join(from_match.group(1).split())
    else:
        from_match_old = re.search(r'from\s+([^\s]+(?:\s+\([^)]+\))?)', raw_header, re.IGNORECASE)
        if from_match_old:
            hop.from_host = from_match_old.group(1)

    by_match = re.search(r'by\s+([^\s;]+)', raw_header, re.IGNORECASE)
    if by_match:
        hop.by_host = by_match.group(1)

    with_match = re.search(r'with\s+([^\s;]+)', raw_header, re.IGNORECASE)
    if with_match:
        hop.with_protocol = with_match.group(1)

    ts_match = re.search(r';\s*(.+)$', raw_header.strip(), re.DOTALL)
    if ts_match:
        hop.timestamp = ' '.join(ts_match.group(1).strip().split())

    return hop


def extract_ip_candidates(text: str) -> List[str]:
    """Extract all valid IPv4 and IPv6 candidate addresses from text in priority order."""
    if not text:
        return []
    candidates = []

    # 1. Bracketed expressions: [192.0.2.1] or [2001:db8::1] or [IPv6:2001:db8::1]
    for b in re.findall(r'\[(?:IPv6:)?([^\]]+)\]', text, re.IGNORECASE):
        cleaned = b.split('%')[0].strip()
        try:
            candidates.append(str(ipaddress.ip_address(cleaned)))
        except ValueError:
            pass

    # 2. IPv6 prefix outside brackets: IPv6:2001:db8::1
    for b in re.findall(r'IPv6:([0-9a-fA-F:]+(?:%[a-zA-Z0-9_-]+)?)', text, re.IGNORECASE):
        cleaned = b.split('%')[0].strip()
        try:
            candidates.append(str(ipaddress.ip_address(cleaned)))
        except ValueError:
            pass

    # 3. Standard IPv4 addresses
    for m in IPV4_PATTERN.findall(text):
        try:
            candidates.append(str(ipaddress.IPv4Address(m)))
        except ValueError:
            pass

    # 4. Standalone IPv6 tokens with at least 2 colons
    for token in re.findall(r'\b[0-9a-fA-F:]{3,}\b', text):
        if token.count(':') >= 2:
            cleaned = token.split('%')[0].strip()
            try:
                ip_obj = ipaddress.ip_address(cleaned)
                if isinstance(ip_obj, ipaddress.IPv6Address):
                    candidates.append(str(ip_obj))
            except ValueError:
                pass

    # Deduplicate while preserving sequence order
    seen = set()
    result = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            result.append(c)

    return result
