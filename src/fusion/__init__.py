"""
Fusion Package
Combines multi-vector intelligence (headers, origin IP, Grok URL analysis, content)
into unified calibrated threat scores.
"""

from .hybrid_score import fuse_threat_intelligence, classify_tier

__all__ = [
    "fuse_threat_intelligence",
    "classify_tier",
]
