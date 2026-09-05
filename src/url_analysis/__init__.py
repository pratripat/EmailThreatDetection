"""
URL Analysis Package
Provides multi-part URL extraction, deterministic feature extraction,
Grok AI threat classification, and persistent SQLite caching.
"""

from .extractor import (
    extract_urls_from_email,
    extract_urls_from_text,
    extract_urls_from_html,
)
from .features import (
    extract_features,
    compute_deterministic_score,
    check_brand_impersonation,
    SHORTENERS,
    SUSPICIOUS_TLDS,
    SUSPICIOUS_KEYWORDS,
)
from .cache import URLCache, get_url_cache
from .grok_client import GrokClient, get_grok_client, GrokUnavailableError
from .analyzer import URLAnalyzer, get_url_analyzer

__all__ = [
    "extract_urls_from_email",
    "extract_urls_from_text",
    "extract_urls_from_html",
    "extract_features",
    "compute_deterministic_score",
    "check_brand_impersonation",
    "SHORTENERS",
    "SUSPICIOUS_TLDS",
    "SUSPICIOUS_KEYWORDS",
    "URLCache",
    "get_url_cache",
    "GrokClient",
    "get_grok_client",
    "GrokUnavailableError",
    "URLAnalyzer",
    "get_url_analyzer",
]
