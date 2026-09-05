"""
Range Lookup Module
Provides indexed CIDR subnet loading and fast O(log N) bisect lookup for IPv4 and IPv6 ranges.
"""

import bisect
import ipaddress
from pathlib import Path
from typing import List, Tuple, Optional


class OriginDataError(Exception):
    """Raised when required IP-range data files are missing or unreadable."""
    pass


def load_cidr_file(filepath: Path) -> List[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse CIDR blocks from a text file."""
    if not filepath.exists():
        raise OriginDataError(f"Required IP data file not found: {filepath}")

    ranges = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                ranges.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                continue

    if not ranges:
        raise OriginDataError(f"Data file {filepath} contains no valid CIDR blocks.")
    return ranges


def build_bisect_index(networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network], version: int):
    """Build sorted (start_int, end_int, cidr_str) index and starts array for binary search."""
    filtered = [n for n in networks if n.version == version]
    indexed = sorted([(int(n.network_address), int(n.broadcast_address), str(n)) for n in filtered])
    starts = [r[0] for r in indexed]
    return indexed, starts


def check_ip_in_indexed_ranges(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address, indexed_ranges, starts) -> Optional[str]:
    """O(log N) binary search lookup of an IP in indexed CIDR ranges."""
    val = int(ip_obj)
    idx = bisect.bisect_right(starts, val) - 1
    if idx >= 0:
        start, end, raw_str = indexed_ranges[idx]
        if start <= val <= end:
            return raw_str
    return None
