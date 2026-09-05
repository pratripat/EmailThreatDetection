"""
Content Feature Extraction Module
Extracts structural, lexical, and psychological coercion features from email text and markup.
"""

import re
from typing import Dict, Any, List


def extract_content_features(subject: str, body_plain: str, body_html: str) -> Dict[str, Any]:
    """
    Extract deterministic lexical and structural features from email text and HTML.
    """
    subject = subject or ""
    body_plain = body_plain or ""
    body_html = body_html or ""
    full_text = f"{subject}\n{body_plain}".strip()

    # Structural indicators
    has_html = bool(body_html)
    has_script_tags = bool(re.search(r'<script\b[^>]*>', body_html, re.IGNORECASE))
    has_hidden_elements = bool(re.search(r'display\s*:\s*none|visibility\s*:\s*hidden', body_html, re.IGNORECASE))
    has_data_uris = bool(re.search(r'data:[^;]+;base64,', body_html, re.IGNORECASE))

    # Lexical features
    char_count = len(full_text)
    word_count = len(full_text.split()) if full_text else 0
    upper_chars = sum(1 for c in full_text if c.isupper())
    upper_ratio = (upper_chars / char_count) if char_count > 0 else 0.0
    exclamation_count = full_text.count("!")

    return {
        "char_count": char_count,
        "word_count": word_count,
        "upper_ratio": round(upper_ratio, 3),
        "exclamation_count": exclamation_count,
        "has_html": has_html,
        "has_script_tags": has_script_tags,
        "has_hidden_elements": has_hidden_elements,
        "has_data_uris": has_data_uris,
    }
