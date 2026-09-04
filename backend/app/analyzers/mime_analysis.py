"""
MIME / Email Parser Module
Uses Python's standard email library (email.policy.default) for robust, RFC 5322/MIME compliant parsing.
Extracts headers, multipart bodies (plain/html), attachment payloads, hashes, and embedded URLs.
Fails gracefully on malformed or truncated inputs.
"""

import email
from email import policy
from email.parser import BytesParser, Parser
import hashlib
import io
import re
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

from .url_analysis import extract_urls, extract_urls_from_html


@dataclass
class AttachmentInfo:
    filename: str
    content_type: str
    size_bytes: int
    sha256: str


@dataclass
class ParsedEmail:
    subject: str = ""
    from_addr: str = ""
    to_addr: str = ""
    to_addrs: List[str] = field(default_factory=list)
    date_str: str = ""
    message_id: Optional[str] = None
    return_path: Optional[str] = None
    reply_to: Optional[str] = None
    received_headers: List[str] = field(default_factory=list)
    auth_results_headers: List[str] = field(default_factory=list)
    dkim_signatures: List[str] = field(default_factory=list)
    body_plain: str = ""
    body_html: str = ""
    attachments: List[AttachmentInfo] = field(default_factory=list)
    embedded_urls: List[str] = field(default_factory=list)
    raw_headers: Dict[str, str] = field(default_factory=dict)
    raw_headers_str: str = ""
    raw_body_str: str = ""
    raw_message: Optional[Any] = None
    parse_errors: List[str] = field(default_factory=list)


def parse_email_bytes(eml_bytes: bytes) -> ParsedEmail:
    """Parse raw email bytes into a structured ParsedEmail object."""
    parsed = ParsedEmail()

    if not eml_bytes or not eml_bytes.strip():
        parsed.parse_errors.append("Empty email input")
        return parsed

    # Extract raw headers string and raw body string directly from payload
    try:
        raw_text = eml_bytes.decode('utf-8', errors='replace')
        if '\r\n\r\n' in raw_text:
            h_part, b_part = raw_text.split('\r\n\r\n', 1)
            parsed.raw_headers_str = h_part
            parsed.raw_body_str = b_part
        elif '\n\n' in raw_text:
            h_part, b_part = raw_text.split('\n\n', 1)
            parsed.raw_headers_str = h_part
            parsed.raw_body_str = b_part
        else:
            parsed.raw_headers_str = raw_text
            parsed.raw_body_str = ""
    except Exception:
        parsed.raw_headers_str = ""
        parsed.raw_body_str = ""

    try:
        msg = BytesParser(policy=policy.default).parsebytes(eml_bytes)
    except Exception as e:
        parsed.parse_errors.append(f"Failed to parse MIME structure: {e}")
        try:
            # Fallback to compat policy
            msg = email.message_from_bytes(eml_bytes)
        except Exception as e2:
            parsed.parse_errors.append(f"Fatal fallback parsing failure: {e2}")
            return parsed

    parsed.raw_message = msg

    # Extract standard headers truthfully: empty strings when headers genuinely do not exist
    parsed.subject = str(msg['Subject']) if msg.get('Subject') is not None else ""
    parsed.from_addr = str(msg['From']) if msg.get('From') is not None else ""
    parsed.to_addr = str(msg['To']) if msg.get('To') is not None else ""
    
    # To headers (list representation for extraction)
    to_header = msg.get('To')
    if to_header:
        parsed.to_addrs = [addr.strip() for addr in str(to_header).split(',') if addr.strip()]
    else:
        parsed.to_addrs = []

    parsed.date_str = str(msg['Date']) if msg.get('Date') is not None else ""
    parsed.message_id = msg.get('Message-ID')
    parsed.return_path = msg.get('Return-Path')
    parsed.reply_to = msg.get('Reply-To')

    # Multi-value headers
    parsed.received_headers = [str(h) for h in msg.get_all('Received', [])]
    parsed.auth_results_headers = [str(h) for h in msg.get_all('Authentication-Results', [])]
    parsed.dkim_signatures = [str(h) for h in msg.get_all('DKIM-Signature', [])]

    # Collect raw headers dictionary
    for k in msg.keys():
        parsed.raw_headers[k] = str(msg.get(k))

    # Extract bodies and attachments from MIME walk
    plain_parts = []
    html_parts = []

    try:
        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = part.get_content_disposition()
                content_type = part.get_content_type()

                if content_disposition == 'attachment' or part.get_filename():
                    # Attachment
                    filename = part.get_filename() or "unnamed_attachment"
                    payload = part.get_payload(decode=True) or b""
                    h = hashlib.sha256(payload).hexdigest()
                    parsed.attachments.append(AttachmentInfo(
                        filename=filename,
                        content_type=content_type,
                        size_bytes=len(payload),
                        sha256=h
                    ))
                elif content_type == 'text/plain':
                    try:
                        content = part.get_content()
                        if isinstance(content, str):
                            plain_parts.append(content)
                        elif isinstance(content, bytes):
                            plain_parts.append(content.decode('utf-8', errors='replace'))
                    except Exception:
                        payload = part.get_payload(decode=True) or b""
                        plain_parts.append(payload.decode('utf-8', errors='replace'))
                elif content_type == 'text/html':
                    try:
                        content = part.get_content()
                        if isinstance(content, str):
                            html_parts.append(content)
                        elif isinstance(content, bytes):
                            html_parts.append(content.decode('utf-8', errors='replace'))
                    except Exception:
                        payload = part.get_payload(decode=True) or b""
                        html_parts.append(payload.decode('utf-8', errors='replace'))
        else:
            # Single part message
            content_type = msg.get_content_type()
            try:
                content = msg.get_content()
                text_str = content if isinstance(content, str) else content.decode('utf-8', errors='replace')
            except Exception:
                payload = msg.get_payload(decode=True) or b""
                text_str = payload.decode('utf-8', errors='replace')

            if content_type == 'text/html':
                html_parts.append(text_str)
            else:
                plain_parts.append(text_str)
    except Exception as e:
        parsed.parse_errors.append(f"Error during MIME part extraction: {e}")

    parsed.body_plain = "\n\n".join(plain_parts)
    parsed.body_html = "\n\n".join(html_parts)

    # Extract URLs from plain text and HTML
    urls = []
    if parsed.body_plain:
        urls.extend(extract_urls(parsed.body_plain))
    if parsed.body_html:
        urls.extend(extract_urls_from_html(parsed.body_html))

    # Also check subject or other headers for URLs
    if 'http' in parsed.subject.lower():
        urls.extend(extract_urls(parsed.subject))

    # Deduplicate preserving order
    seen_urls = set()
    deduped_urls = []
    for u in urls:
        if u not in seen_urls:
            seen_urls.add(u)
            deduped_urls.append(u)
    parsed.embedded_urls = deduped_urls

    return parsed


def parse_email_file(filepath: str) -> ParsedEmail:
    """Read .eml file and parse its contents."""
    with open(filepath, 'rb') as f:
        return parse_email_bytes(f.read())
