"""
IP Classifier
Classifies IPv4 and IPv6 addresses into standard categories (global, private, bogon, etc.).
"""

import ipaddress
from typing import Union


def classify_ip_type(ip_obj: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address]) -> str:
    """Classify an IPv4 or IPv6 address object into its standard network category."""
    if isinstance(ip_obj, str):
        try:
            ip_obj = ipaddress.ip_address(ip_obj.strip())
        except ValueError:
            return "invalid"

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
