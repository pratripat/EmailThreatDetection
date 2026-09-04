"""
Origin Analysis Module — SIH26106 prototype

Reframes the "GeoLocation" requirement per the actual PS text:
"Correlation with VPN, TOR, open relay, botnet, or cloud-hosted infrastructure indicators"

Instead of naively pinning an IP to a city (which VPNs/proxies defeat trivially),
this answers: "Is this IP a residential connection, or known anonymization/hosting
infrastructure?" — a question that survives the VPN objection.

Data source: X4BNet/lists_vpn (public, actively maintained on GitHub)
- datacenter/ipv4.txt: known hosting/cloud provider ranges
- vpn/ipv4.txt: known commercial VPN provider ranges
"""

import ipaddress
from dataclasses import dataclass
from typing import Optional
from pathlib import Path


@dataclass
class OriginAssessment:
    ip: str
    is_datacenter: bool = False
    is_vpn: bool = False
    matched_range: Optional[str] = None
    confidence_label: str = "UNKNOWN"
    explanation: str = ""


def _load_ranges(filepath: str) -> list:
    ranges = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                ranges.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                continue
    return ranges


class OriginAnalyzer:
    def __init__(self, data_dir: str = None):
        data_dir = data_dir or str(Path(__file__).parent.parent / 'data')
        self.datacenter_ranges = _load_ranges(f"{data_dir}/datacenter_ranges.txt")
        self.vpn_ranges = _load_ranges(f"{data_dir}/vpn_ranges.txt")

    def _check_ranges(self, ip_obj, ranges: list) -> Optional[str]:
        for network in ranges:
            if ip_obj in network:
                return str(network)
        return None

    def assess(self, ip_str: str) -> OriginAssessment:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return OriginAssessment(ip=ip_str, confidence_label="INVALID_IP",
                                     explanation="Not a valid IP address")

        result = OriginAssessment(ip=ip_str)

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

        result.confidence_label = "MEDIUM-HIGH"
        result.explanation = (
            "IP does not match known VPN or datacenter ranges — consistent with an "
            "ordinary residential/ISP connection. Geolocation is more likely to reflect "
            "genuine sender location, though this is not certain proof."
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
