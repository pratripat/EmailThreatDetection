"""
Domain Analysis Utilities
Provides PSL-aware registrable domain resolution, IDN/Punycode normalization,
homoglyph translation, brand list loading, and domain relationship analysis.
"""

from enum import Enum
import unicodedata
import json
from pathlib import Path
from typing import Tuple, List, Optional
import tldextract
import difflib

from config.settings import BRAND_LIST_PATH

# Homoglyph translation table (Cyrillic/Greek lookalikes in Latin text)
HOMOGLYPH_MAP = str.maketrans({
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',
    'у': 'y', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'В': 'b',
    'А': 'a', 'Е': 'e', 'О': 'o', 'Р': 'p', 'С': 'c', 'Т': 't'
})

# Offline-safe PSL extractor
_tld_extractor = tldextract.TLDExtract(suffix_list_urls=())


class DomainRelation(Enum):
    EXACT_MATCH = "EXACT_MATCH"
    SUBDOMAIN_RELATION = "SUBDOMAIN_RELATION"
    SAME_REGISTRABLE_DOMAIN = "SAME_REGISTRABLE_DOMAIN"
    PARENT_CHILD = "PARENT_CHILD"
    SIBLING = "SIBLING"
    UNRELATED = "UNRELATED"


def load_brand_list() -> List[str]:
    """Load protected brands list from JSON or return default fallback."""
    if BRAND_LIST_PATH.exists():
        try:
            with open(BRAND_LIST_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return [
        "paypal", "google", "microsoft", "apple", "amazon",
        "netflix", "chase", "wellsfargo", "facebook", "instagram"
    ]


def normalize_domain(domain: str) -> str:
    """Normalize domain to canonical lowercase ASCII/Punycode."""
    if not domain:
        return ""
    domain = domain.strip().lower()
    if domain.endswith('.'):
        domain = domain[:-1]
    try:
        import idna
        return idna.encode(domain, uts46=True).decode('ascii')
    except Exception:
        try:
            return domain.encode('idna').decode('ascii')
        except Exception:
            return domain


def registrable_domain(domain: str) -> str:
    """Extract registrable domain (e.g., mail.college.edu -> college.edu)."""
    if not domain:
        return ""
    norm = normalize_domain(domain)
    ext = _tld_extractor(norm)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    elif ext.domain:
        return ext.domain
    return norm


def domain_relationship(d1: str, d2: str) -> DomainRelation:
    """Analyze hierarchical relationship between two domains."""
    if not d1 or not d2:
        return DomainRelation.UNRELATED

    norm1 = normalize_domain(d1)
    norm2 = normalize_domain(d2)

    if norm1 == norm2:
        return DomainRelation.EXACT_MATCH

    reg1 = registrable_domain(norm1)
    reg2 = registrable_domain(norm2)

    if reg1 and reg2 and reg1 == reg2:
        if norm1.endswith("." + norm2) or norm2.endswith("." + norm1):
            return DomainRelation.SUBDOMAIN_RELATION
        return DomainRelation.SAME_REGISTRABLE_DOMAIN

    if norm1.endswith("." + norm2) or norm2.endswith("." + norm1):
        return DomainRelation.SUBDOMAIN_RELATION

    return DomainRelation.UNRELATED
