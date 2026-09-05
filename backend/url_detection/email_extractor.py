import re
from email import message_from_string
from typing import Set

class EmailURLExtractor:
    """Extract URLs from email content"""
    
    URL_PATTERN = re.compile(
        r'https?://[^\s<>"\'()\[\]{}\s]+', 
        re.IGNORECASE
    )
    
    @staticmethod
    def extract_from_eml(eml_content: str) -> Set[str]:
        """Extract all URLs from an EML file content"""
        urls = set()
        
        # Parse email
        msg = message_from_string(eml_content)
        
        # Extract from body
        body = EmailURLExtractor._get_body(msg)
        if body:
            urls.update(EmailURLExtractor.URL_PATTERN.findall(body))
        
        # Extract from headers (if needed)
        for header in ['Reply-To', 'Return-Path']:
            value = msg.get(header, '')
            if value:
                urls.update(EmailURLExtractor.URL_PATTERN.findall(value))
        
        return urls
    
    @staticmethod
    def _get_body(msg) -> str:
        """Extract plain text body"""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    return part.get_payload(decode=True).decode('utf-8', errors='ignore')
        return msg.get_payload(decode=True).decode('utf-8', errors='ignore')