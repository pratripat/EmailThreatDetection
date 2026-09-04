"""
Origin Analysis Module — SIH26106 prototype (V1 — bugs fixed per agent audit)

Reframes the "GeoLocation" requirement per the actual PS text:
"Correlation with VPN, TOR, open relay, botnet, or cloud-hosted infrastructure indicators"

Instead of naively pinning an IP to a city (which VPNs/proxies defeat trivially),
this answers: "Is this IP a residential connection, or known anonymization/hosting
infrastructure?" — a question that survives the VPN objection.

Data source: X4BNet/lists_vpn (public, actively maintained on GitHub)
- output/datacenter/ipv4.txt: known hosting/cloud provider ranges (CORRECTED PATH —
  the old `datacenter/ipv4.txt` path is stale/deprecated)
- output/vpn/ipv4.txt: known commercial VPN provider ranges (CORRECTED PATH)

Download commands (for bootstrapping data/ if missing):
    curl -o data/datacenter_ranges.txt \\
        https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt
    curl -o data/vpn_ranges.txt \\
        https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt

KNOWN LIMITATION (surfaced honestly, not just in this comment — see UNKNOWN label below):
these lists are not exhaustive. An IP that matches neither list is NOT proven to be a
genuine residential connection — it may simply be an unlisted VPN/datacenter/hosting IP.
Absence of a match is reported as UNKNOWN, never as a positive "residential" verdict.
"""

import bisect
import ipaddress
from dataclasses import dataclass
from typing import Optional
from pathlib import Path


class OriginDataError(Exception):
    """Raised when required IP-range data files are missing or unreadable.
    Deliberately NOT a bare FileNotFoundError — callers should catch this
    specifically and refuse to produce a confidence verdict rather than
    silently guessing."""
    pass


def classify_ip_type(ip_obj) -> str:
    """Classify an IPv4 or IPv6 address object into its standard network category.
    Returns: 'multicast', 'loopback', 'link_local', 'private', 'reserved',
    'documentation_or_special', or 'global'."""
    if ip_obj.is_multicast:
        return "multicast"
    if ip_obj.is_loopback:
        return "loopback"
    if ip_obj.is_link_local:
        return "link_local"
    if ip_obj.is_private:
        return "private"
    if ip_obj.is_reserved:
        return "reserved"
    if not ip_obj.is_global:
        return "documentation_or_special"
    return "global"


@dataclass
class OriginAssessment:
    ip: str
    is_datacenter: bool = False
    is_vpn: bool = False
    is_non_global: bool = False       # reserved / private / loopback / documentation / multicast
    non_global_reason: Optional[str] = None
    matched_range: Optional[str] = None
    confidence_label: str = "UNKNOWN"
    explanation: str = ""


def _load_ranges(*filepaths: str) -> list:
    ranges = []
    for filepath in filepaths:
        path = Path(filepath)
        if not path.exists():
            fname = path.name
            if 'datacenter' in fname and 'ipv6' in fname:
                subpath = 'output/datacenter/ipv6.txt'
            elif 'datacenter' in fname:
                subpath = 'output/datacenter/ipv4.txt'
            elif 'vpn' in fname and 'ipv6' in fname:
                subpath = 'output/vpn/ipv6.txt'
            else:
                subpath = 'output/vpn/ipv4.txt'
            raise OriginDataError(
                f"Required data file not found: {filepath}\n"
                f"This module cannot assess IP origin without it — refusing to guess.\n"
                f"Download it with:\n"
                f"  curl -o {filepath} "
                f"https://raw.githubusercontent.com/X4BNet/lists_vpn/main/{subpath}"
            )
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    ranges.append(ipaddress.ip_network(line, strict=False))
                except ValueError:
                    continue
    if not ranges:
        raise OriginDataError(
            f"Data file(s) {filepaths} contain no valid IP ranges — "
            f"treating as corrupt/empty, refusing to guess."
        )
    return ranges


class OriginAnalyzer:
    def __init__(self, data_dir: str = None):
        if data_dir is None:
            # Check candidate directories: backend/data, repo/data
            candidates = [
                Path(__file__).resolve().parent.parent.parent / 'data',  # backend/data
                Path(__file__).resolve().parent.parent / 'data',         # backend/app/data
                Path.cwd() / 'backend' / 'data',
                Path.cwd() / 'data',
            ]
            for c in candidates:
                if (c / 'datacenter_ranges.txt').exists():
                    data_dir = str(c)
                    break
            if data_dir is None:
                data_dir = str(Path(__file__).resolve().parent.parent.parent / 'data')
        # Load both IPv4 and IPv6 range lists for full dual-stack coverage
        self.datacenter_ranges = _load_ranges(
            f"{data_dir}/datacenter_ranges.txt",
            f"{data_dir}/datacenter_ipv6_ranges.txt"
        )
        self.vpn_ranges = _load_ranges(
            f"{data_dir}/vpn_ranges.txt",
            f"{data_dir}/vpn_ipv6_ranges.txt"
        )
        # V2 Performance fix: Build sorted integer indices for bisect-based O(log N) lookups
        self.datacenter_v4_ranges, self.datacenter_v4_starts = self._build_index(self.datacenter_ranges, version=4)
        self.datacenter_v6_ranges, self.datacenter_v6_starts = self._build_index(self.datacenter_ranges, version=6)
        self.vpn_v4_ranges, self.vpn_v4_starts = self._build_index(self.vpn_ranges, version=4)
        self.vpn_v6_ranges, self.vpn_v6_starts = self._build_index(self.vpn_ranges, version=6)

    @staticmethod
    def _build_index(networks: list, version: int):
        filtered = [n for n in networks if n.version == version]
        indexed = sorted([(int(n.network_address), int(n.broadcast_address), str(n)) for n in filtered])
        starts = [r[0] for r in indexed]
        return indexed, starts

    def _check_ranges_indexed(self, ip_obj, indexed_ranges, starts) -> Optional[str]:
        val = int(ip_obj)
        idx = bisect.bisect_right(starts, val) - 1
        if idx >= 0:
            start, end, raw_str = indexed_ranges[idx]
            if start <= val <= end:
                return raw_str
        return None

    def _check_ranges(self, ip_obj, ranges: list = None) -> Optional[str]:
        # Fast path using precomputed bisect indices
        if ranges is self.vpn_ranges or ranges is None:
            if ip_obj.version == 4:
                return self._check_ranges_indexed(ip_obj, self.vpn_v4_ranges, self.vpn_v4_starts)
            else:
                return self._check_ranges_indexed(ip_obj, self.vpn_v6_ranges, self.vpn_v6_starts)
        elif ranges is self.datacenter_ranges:
            if ip_obj.version == 4:
                return self._check_ranges_indexed(ip_obj, self.datacenter_v4_ranges, self.datacenter_v4_starts)
            else:
                return self._check_ranges_indexed(ip_obj, self.datacenter_v6_ranges, self.datacenter_v6_starts)
        else:
            # Fallback for arbitrary custom ranges
            for network in ranges:
                if ip_obj.version == network.version and ip_obj in network:
                    return str(network)
            return None

    def _check_non_global(self, ip_obj) -> Optional[str]:
        """V2 fix: multicast/reserved/private/documentation/loopback IPs must never be
        reported as 'residential' — real internet mail should never legitimately
        carry these in a Received: header."""
        if ip_obj.is_multicast:
            return "multicast address — cannot originate unicast SMTP traffic or valid mail relays"
        if ip_obj.is_loopback:
            return "loopback address (127.0.0.0/8 or ::1) — never valid in a real mail relay chain"
        if ip_obj.is_private:
            # NOTE: Python's ipaddress.is_private is broader than RFC1918 — it also
            # covers IANA special-use/documentation ranges like RFC 5737
            # (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). Don't name a specific
            # RFC here; the message stays accurate across all cases this flag covers.
            return "private or special-use address (not a real internet-routable host)"
        if ip_obj.is_reserved:
            return "IANA-reserved address space — not a valid internet-routable IP"
        if not ip_obj.is_global:
            # Catches documentation ranges (RFC 5737: 192.0.2.0/24, 198.51.100.0/24,
            # 203.0.113.0/24) and other non-global special-use ranges not covered above.
            return "non-global/special-use address (e.g. RFC 5737 documentation range) — not a real internet host"
        return None

    def assess(self, ip_str: str) -> OriginAssessment:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return OriginAssessment(ip=ip_str, confidence_label="INVALID_IP",
                                     explanation="Not a valid IP address")

        result = OriginAssessment(ip=ip_str)

        # Bug #3: check non-global/reserved/private BEFORE falling through to the
        # VPN/datacenter/unknown logic — these are a distinct, higher-priority case.
        non_global_reason = self._check_non_global(ip_obj)
        if non_global_reason:
            result.is_non_global = True
            result.non_global_reason = non_global_reason
            result.confidence_label = "INVALID_FOR_INTERNET"
            result.explanation = (
                f"This IP is {non_global_reason}. Its presence in an email's relay "
                f"chain is itself anomalous — either a misconfigured/internal test "
                f"system, or a deliberately fabricated header. Not evidence of a "
                f"genuine residential connection."
            )
            return result

        vpn_match = self._check_ranges(ip_obj, self.vpn_ranges)
        if vpn_match:
            result.is_vpn = True
            result.matched_range = vpn_match
            result.confidence_label = "LOW"
            result.explanation = (
                f"IP falls within a known commercial VPN provider range ({vpn_match}). "
                f"True origin cannot be determined — sender deliberately obscured location."
            )
            return result

        dc_match = self._check_ranges(ip_obj, self.datacenter_ranges)
        if dc_match:
            result.is_datacenter = True
            result.matched_range = dc_match
            result.confidence_label = "LOW-MEDIUM"
            result.explanation = (
                f"IP falls within a known datacenter/hosting range ({dc_match}). "
                f"This is likely a cloud server, compromised host, or relay — not a "
                f"residential connection. Treat any 'location' as the server's, not the sender's."
            )
            return result

        # Bug #4 fix: no match does NOT mean "probably residential." It means our
        # lists don't cover this IP. These lists are known-incomplete — say so.
        result.confidence_label = "UNKNOWN"
        result.explanation = (
            "NOT IN KNOWN LISTS — could be an ordinary residential connection, OR an "
            "unlisted VPN/datacenter/hosting IP our data doesn't yet cover. Absence "
            "from these lists is not proof of legitimacy. Treat any geolocation derived "
            "from this IP as unverified, not confirmed."
        )
        return result


if __name__ == '__main__':
    analyzer = OriginAnalyzer()

    test_ips = [
        "45.135.232.19",   # from our spoofed sample
        "203.0.113.44",    # from our clean sample
        "185.220.101.47",  # known Tor-adjacent / relay-style range for testing
    ]

    for ip in test_ips:
        result = analyzer.assess(ip)
        print(f"\nIP: {result.ip}")
        print(f"  Confidence: {result.confidence_label}")
        print(f"  VPN: {result.is_vpn} | Datacenter: {result.is_datacenter}")
        print(f"  {result.explanation}")
