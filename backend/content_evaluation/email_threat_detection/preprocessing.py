"""Email text preprocessing and structural formatting for Gaykar/PhishingDistilBERT.

This module converts raw email subject and body into the exact structural representation
expected by the pretrained model:
    [SSUB] <subject> [ESUB] [SBODY] <body> [EBODY]

URLs are conservatively replaced with [LINK] and phone numbers with [PHONE].
No aggressive NLP cleaning (no stopword removal, no stemming/lemmatization,
no manual lowercasing) is performed to preserve natural transformer semantics.
"""

import html
import re
from typing import Optional

# Regex for detecting URLs (handles http, https, and www prefixes)
# Strips common trailing sentence punctuation from the matched URL
URL_PATTERN = re.compile(
    r'(?:https?://|www\.)[^\s<>"\'{}|\\^`]+[^\s<>"\'{}|\\^`.,;:!?)\]]',
    re.IGNORECASE
)

# Regex for detecting common international and domestic phone number formats
# (e.g., +1-800-555-0199, (555) 123-4567, +91 98765 43210, 800-555-0199)
PHONE_CANDIDATE_PATTERN = re.compile(
    r'(?:\+?\d{1,4}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{3,4}\b'
)

# Regex for HTML tags
HTML_TAG_PATTERN = re.compile(r'<[^>]+>')
HTML_LINE_BREAK_PATTERN = re.compile(r'<(?:br|p|div|tr|h[1-6])\s*/?>', re.IGNORECASE)


def extract_clean_text_from_html(raw_html: str) -> str:
    """Extract plain text from HTML content if HTML markup is present.
    
    Converts line-breaking tags to newlines, removes tags, and unescapes entities.
    """
    if not raw_html or not isinstance(raw_html, str):
        return ""
    
    # Check if string contains HTML markup
    if not ('<' in raw_html and '>' in raw_html):
        return raw_html

    # Replace line break and paragraph tags with newlines
    text = HTML_LINE_BREAK_PATTERN.sub('\n', raw_html)
    # Strip remaining HTML tags
    text = HTML_TAG_PATTERN.sub(' ', text)
    # Unescape HTML entities (e.g., &amp; -> &, &nbsp; -> space)
    text = html.unescape(text)
    return text


def replace_urls(text: str, link_token: str = "[LINK]") -> str:
    """Conservatively replace URLs with the model's structural [LINK] token."""
    if not text:
        return ""
    return URL_PATTERN.sub(link_token, text)


def replace_phone_numbers(text: str, phone_token: str = "[PHONE]") -> str:
    """Conservatively replace telephone numbers with the model's structural [PHONE] token.
    
    Filters candidates to ensure between 7 and 15 total digits to avoid replacing
    short numbers, dates, or currency amounts.
    """
    if not text:
        return ""

    def _phone_sub(match: re.Match) -> str:
        candidate = match.group(0)
        digits_only = re.sub(r'\D', '', candidate)
        # Phone numbers typically have between 7 and 15 digits (E.164 standard)
        if 7 <= len(digits_only) <= 15:
            return phone_token
        return candidate

    return PHONE_CANDIDATE_PATTERN.sub(_phone_sub, text)


def clean_whitespace(text: str) -> str:
    """Normalize irregular whitespace, consecutive tabs, and excessive blank lines.
    
    Preserves basic paragraph structure while stripping zero-width or redundant spaces.
    """
    if not text:
        return ""
    # Normalize unicode spaces and null bytes
    text = text.replace('\x00', '').replace('\r\n', '\n').replace('\r', '\n')
    # Collapse multiple inline spaces/tabs to a single space
    text = re.sub(r'[ \t]+', ' ', text)
    # Collapse 3 or more consecutive newlines into 2
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()


def preprocess_text_content(text: Optional[str]) -> str:
    """Clean and normalize a single text field (subject or body).
    
    1. Gracefully handles None or non-string inputs.
    2. Strips HTML if present.
    3. Normalizes whitespace.
    4. Replaces URLs with [LINK].
    5. Replaces phone numbers with [PHONE].
    """
    if text is None:
        return ""
    
    if not isinstance(text, str):
        text = str(text)

    # 1. HTML parsing if necessary
    text = extract_clean_text_from_html(text)
    
    # 2. Normalize whitespace
    text = clean_whitespace(text)

    # 3. Replace URLs
    text = replace_urls(text)

    # 4. Replace Phone numbers
    text = replace_phone_numbers(text)

    return text.strip()


def format_email_for_model(subject: Optional[str], body: Optional[str]) -> str:
    """Format subject and body into the exact special-token format required by PhishingDistilBERT.
    
    Format:
        [SSUB] <subject> [ESUB] [SBODY] <body> [EBODY]
    
    Handles empty, missing, or None fields gracefully without crashing.
    """
    clean_sub = preprocess_text_content(subject)
    clean_bod = preprocess_text_content(body)

    # Build the structural string
    # Even if subject or body is empty, we keep the structural boundary tokens
    formatted = f"[SSUB] {clean_sub} [ESUB] [SBODY] {clean_bod} [EBODY]"
    
    # Clean up any duplicate spacing inside markers
    return re.sub(r'\s+', ' ', formatted).strip()
