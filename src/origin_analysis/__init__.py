"""
Origin Analysis Package
Provides IP classification, CIDR indexing, datacenter and VPN range lookups.
"""

from .ip_classifier import classify_ip_type
from .range_lookup import load_cidr_file, build_bisect_index, check_ip_in_indexed_ranges, OriginDataError
from .analyzer import OriginAnalyzer, get_origin_analyzer

__all__ = [
    "classify_ip_type",
    "load_cidr_file",
    "build_bisect_index",
    "check_ip_in_indexed_ranges",
    "OriginDataError",
    "OriginAnalyzer",
    "get_origin_analyzer",
]
