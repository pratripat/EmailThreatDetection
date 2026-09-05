"""
Origin IP Analyzer
Evaluates email sender/origin IP addresses against datacenter and VPN CIDR ranges
and standard IP network classifications.
"""

import ipaddress
import logging
from pathlib import Path
from typing import Dict, Any, Optional

from config import settings
from .ip_classifier import classify_ip_type
from .range_lookup import load_cidr_file, build_bisect_index, check_ip_in_indexed_ranges, OriginDataError

logger = logging.getLogger("origin_analysis")


class OriginAnalyzer:
    """Analyzer for origin IP addresses evaluating infrastructure type and threat risk."""

    def __init__(self, ip_ranges_dir: Optional[Path] = None):
        self.ip_ranges_dir = ip_ranges_dir or settings.IP_RANGES_DIR
        self._initialized = False

        # Bisect index containers: (indexed_ranges, starts)
        self.dc_v4_idx = ([], [])
        self.dc_v6_idx = ([], [])
        self.vpn_v4_idx = ([], [])
        self.vpn_v6_idx = ([], [])

        self._load_indices()

    def _load_indices(self) -> None:
        """Load and index CIDR files for fast binary search."""
        try:
            # Datacenter ranges
            dc_v4_file = self.ip_ranges_dir / "datacenter_ipv4.txt"
            dc_v6_file = self.ip_ranges_dir / "datacenter_ipv6.txt"
            if dc_v4_file.exists():
                v4_nets = load_cidr_file(dc_v4_file)
                self.dc_v4_idx = build_bisect_index(v4_nets, version=4)
            if dc_v6_file.exists():
                v6_nets = load_cidr_file(dc_v6_file)
                self.dc_v6_idx = build_bisect_index(v6_nets, version=6)

            # VPN ranges
            vpn_v4_file = self.ip_ranges_dir / "vpn_ipv4.txt"
            vpn_v6_file = self.ip_ranges_dir / "vpn_ipv6.txt"
            if vpn_v4_file.exists():
                vpn_v4_nets = load_cidr_file(vpn_v4_file)
                self.vpn_v4_idx = build_bisect_index(vpn_v4_nets, version=4)
            if vpn_v6_file.exists():
                vpn_v6_nets = load_cidr_file(vpn_v6_file)
                self.vpn_v6_idx = build_bisect_index(vpn_v6_nets, version=6)

            self._initialized = True
        except OriginDataError as e:
            logger.warning(f"Origin IP data files incomplete: {e}. Origin analysis running with partial data.")
        except Exception as e:
            logger.error(f"Error loading origin IP range indices: {e}")

    def analyze(self, ip_str: str) -> Dict[str, Any]:
        """
        Analyze an IP address string.
        Returns a dictionary with classification, datacenter/VPN status, and risk flags.
        """
        clean_ip = ip_str.strip() if ip_str else ""
        if not clean_ip:
            return {
                "ip": "",
                "valid": False,
                "version": None,
                "classification": "missing",
                "is_datacenter": False,
                "datacenter_range": None,
                "is_vpn": False,
                "vpn_range": None,
                "risk_score": 0.0,
                "reasons": ["No IP provided"]
            }

        try:
            ip_obj = ipaddress.ip_address(clean_ip)
        except ValueError:
            return {
                "ip": clean_ip,
                "valid": False,
                "version": None,
                "classification": "invalid",
                "is_datacenter": False,
                "datacenter_range": None,
                "is_vpn": False,
                "vpn_range": None,
                "risk_score": 50.0,
                "reasons": ["Invalid IP address format"]
            }

        classification = classify_ip_type(ip_obj)
        is_dc = False
        dc_range = None
        is_vpn = False
        vpn_range = None
        reasons = []
        risk_score = 0.0

        if classification not in ("global", "private"):
            reasons.append(f"Non-standard IP classification: {classification}")
            risk_score += 30.0

        if ip_obj.version == 4:
            if self.dc_v4_idx[0]:
                dc_range = check_ip_in_indexed_ranges(ip_obj, self.dc_v4_idx[0], self.dc_v4_idx[1])
                if dc_range:
                    is_dc = True
                    reasons.append(f"Matches datacenter/cloud CIDR block: {dc_range}")
                    risk_score += 35.0

            if self.vpn_v4_idx[0]:
                vpn_range = check_ip_in_indexed_ranges(ip_obj, self.vpn_v4_idx[0], self.vpn_v4_idx[1])
                if vpn_range:
                    is_vpn = True
                    reasons.append(f"Matches commercial/known VPN CIDR block: {vpn_range}")
                    risk_score += 45.0
        else:
            if self.dc_v6_idx[0]:
                dc_range = check_ip_in_indexed_ranges(ip_obj, self.dc_v6_idx[0], self.dc_v6_idx[1])
                if dc_range:
                    is_dc = True
                    reasons.append(f"Matches datacenter/cloud IPv6 CIDR block: {dc_range}")
                    risk_score += 35.0

            if self.vpn_v6_idx[0]:
                vpn_range = check_ip_in_indexed_ranges(ip_obj, self.vpn_v6_idx[0], self.vpn_v6_idx[1])
                if vpn_range:
                    is_vpn = True
                    reasons.append(f"Matches commercial/known VPN IPv6 CIDR block: {vpn_range}")
                    risk_score += 45.0

        risk_score = min(100.0, risk_score)

        return {
            "ip": str(ip_obj),
            "valid": True,
            "version": ip_obj.version,
            "classification": classification,
            "is_datacenter": is_dc,
            "datacenter_range": dc_range,
            "is_vpn": is_vpn,
            "vpn_range": vpn_range,
            "risk_score": risk_score,
            "reasons": reasons
        }


# Global singleton instance
_default_analyzer: Optional[OriginAnalyzer] = None


def get_origin_analyzer() -> OriginAnalyzer:
    """Get or instantiate singleton OriginAnalyzer."""
    global _default_analyzer
    if _default_analyzer is None:
        _default_analyzer = OriginAnalyzer()
    return _default_analyzer
