"""
URL Extraction Engine
Extracts, decodes, and normalizes URLs from raw text, HTML content,
and RFC 822 / MIME email messages.
"""

import re
from email import message_from_bytes, message_from_string
from email.message import Message
from typing import List, Union, Set
from urllib.parse import urlparse

URL_REGEX = re.compile(
    r'(?:https?://|www\.)[^\s<>"\'{}|\\^`\[\]()]+',
    re.IGNORECASE
)
HREF_REGEX = re.compile(
    r'href=["\']\s*(https?://[^\s"\'<>]+)\s*["\']',
    re.IGNORECASE
)
SRC_REGEX = re.compile(
    r'src=["\']\s*(https?://[^\s"\'<>]+)\s*["\']',
    re.IGNORECASE
)


def extract_urls_from_text(text: str) -> List[str]:
    """Extract all HTTP/HTTPS and www URLs from plain text."""
    if not text:
        return []

    # Clean whitespace in broken protocols e.g. "http : //" -> "http://"
    sanitized = re.sub(r'(https?)\s*:\s*/\s*/', r'\1://', text)
    matches = URL_REGEX.findall(sanitized)
    results: List[str] = []

    for m in matches:
        # Strip trailing punctuation often captured at sentence ends
        cleaned = re.sub(r'[,.;:!?\)\]>]+$', '', m).strip()
        if cleaned.startswith("www."):
            cleaned = "http://" + cleaned
        if cleaned.startswith("http://") or cleaned.startswith("https://"):
            results.append(cleaned)

    return results


def extract_urls_from_html(html_content: str) -> List[str]:
    """Extract URLs from HTML attributes (href, src) and fallback text scanning."""
    if not html_content:
        return []

    urls: List[str] = []
    # 1. Look for href attributes
    for href in HREF_REGEX.findall(html_content):
        cleaned = href.strip().rstrip(".,;:")
        if cleaned.startswith("http://") or cleaned.startswith("https://"):
            urls.append(cleaned)

    # 2. Look for src attributes
    for src in SRC_REGEX.findall(html_content):
        cleaned = src.strip().rstrip(".,;:")
        if cleaned.startswith("http://") or cleaned.startswith("https://"):
            urls.append(cleaned)

    # 3. Plain text regex fallback
    urls.extend(extract_urls_from_text(html_content))

    # Deduplicate preserving order
    seen: Set[str] = set()
    deduped: List[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            deduped.append(u)
    return deduped


def extract_urls_from_email(eml_content: Union[str, bytes, Message]) -> List[str]:
    """
    Extract all URLs from an email, inspecting headers (Reply-To, List-Unsubscribe, etc.),
    text/plain bodies, and text/html bodies.
    """
    if isinstance(eml_content, bytes):
        msg = message_from_bytes(eml_content)
    elif isinstance(eml_content, str):
        msg = message_from_string(eml_content)
    elif isinstance(eml_content, Message):
        msg = eml_content
    else:
        return []

    urls: List[str] = []

    # 1. Header URL extraction
    for hdr, val in msg.items():
        if val:
            val_str = str(val)
            fixed_val = re.sub(r'(https?)\s*:\s*/\s*/', r'\1://', val_str)
            urls.extend(extract_urls_from_text(fixed_val))

    # 2. Walk body parts
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type in ["text/plain", "text/html"]:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    text = payload.decode(charset, errors="ignore")
                    if content_type == "text/html":
                        urls.extend(extract_urls_from_html(text))
                    else:
                        urls.extend(extract_urls_from_text(text))
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="ignore")
            if msg.get_content_type() == "text/html":
                urls.extend(extract_urls_from_html(text))
            else:
                urls.extend(extract_urls_from_text(text))

    # Deduplicate preserving order
    seen: Set[str] = set()
    deduped: List[str] = []
    for u in urls:
        cleaned = u.strip()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            deduped.append(cleaned)

    return deduped
