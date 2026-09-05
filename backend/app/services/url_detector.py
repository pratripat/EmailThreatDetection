# backend/app/services/url_detector.py
import os
import re
from email import message_from_string
from typing import Set, List, Dict, Any, Optional
from openai import OpenAI
from pathlib import Path
from dotenv import load_dotenv
import logging

logger = logging.getLogger(__name__)

# Load .env from root
root_dir = Path(__file__).parent.parent.parent.parent
env_path = root_dir / '.env'
load_dotenv(env_path)

class GrokURLDetector:
    """Grok-powered URL detection service for email threat analysis"""
    
    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY") or os.getenv("GROK_API_KEY") or os.getenv("XAI_API_KEY")
        if not self.api_key or self.api_key.strip().startswith("xai-example-key"):
            logger.warning("OPENAI_API_KEY not configured or is placeholder - URL detection will be limited")
            self.enabled = False
        else:
            self.enabled = True
            self.client = OpenAI(
                api_key=self.api_key.strip(),
                base_url="https://api.x.ai/v1"
            )
            self.model = "grok-4.6"
    
    def extract_urls_from_email(self, eml_content: str) -> Set[str]:
        """Extract URLs from email content"""
        url_pattern = re.compile(r'https?://[^\s<>"\'()\[\]{}\s]+', re.IGNORECASE)
        urls = set()
        
        try:
            msg = message_from_string(eml_content)
            
            # Extract from body
            body = self._get_body(msg)
            if body:
                urls.update(url_pattern.findall(body))
            
            # Extract from headers
            for header in ['Reply-To', 'Return-Path', 'From', 'Sender']:
                value = msg.get(header, '')
                if value:
                    urls.update(url_pattern.findall(value))
                    
        except Exception as e:
            logger.error(f"Error extracting URLs: {e}")
        
        return urls
    
    def _get_body(self, msg) -> str:
        """Extract plain text body"""
        try:
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        return part.get_payload(decode=True).decode('utf-8', errors='ignore')
            return msg.get_payload(decode=True).decode('utf-8', errors='ignore')
        except:
            return ""
    
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze a single URL using Grok"""
        if not self.enabled:
            return {
                'url': url,
                'verdict': 'UNKNOWN',
                'confidence': 0.0,
                'source': 'grok_disabled',
                'error': 'Grok API key not configured'
            }
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "user",
                        "content": f"Classify this URL for security threats. Reply with ONLY ONE WORD: BENIGN, PHISHING, MALICIOUS, or SUSPICIOUS. URL: {url}"
                    }
                ],
                max_tokens=20,
                temperature=0.1
            )
            
            result = (response.choices[0].message.content or "").strip().upper()
            if "PHISHING" in result:
                result = "PHISHING"
            elif "MALICIOUS" in result:
                result = "MALICIOUS"
            elif "SUSPICIOUS" in result:
                result = "SUSPICIOUS"
            elif "BENIGN" in result:
                result = "BENIGN"
            else:
                result = "UNKNOWN"
            
            # Map verdict to confidence
            confidence_map = {
                'BENIGN': 0.9,
                'PHISHING': 0.85,
                'MALICIOUS': 0.9,
                'SUSPICIOUS': 0.6,
                'UNKNOWN': 0.3
            }
            
            return {
                'url': url,
                'verdict': result,
                'confidence': confidence_map.get(result, 0.5),
                'source': 'grok'
            }
        except Exception as e:
            logger.error(f"Error analyzing URL {url}: {e}")
            return {
                'url': url,
                'verdict': 'ERROR',
                'confidence': 0.0,
                'source': 'grok',
                'error': str(e)
            }
    
    def analyze_email_urls(self, eml_content: str) -> Dict[str, Any]:
        """Extract and analyze all URLs in an email"""
        # Extract URLs
        urls = self.extract_urls_from_email(eml_content)
        
        if not urls:
            return {
                'urls_found': [],
                'url_analysis': [],
                'summary': {
                    'total_urls': 0,
                    'malicious': 0,
                    'suspicious': 0,
                    'benign': 0,
                    'unknown': 0,
                    'risk_level': 'LOW',
                    'message': 'No URLs found in email'
                }
            }
        
        # Analyze each URL
        results = [self.analyze_url(url) for url in urls]
        
        # Summarize
        verdicts = [r.get('verdict', 'UNKNOWN') for r in results]
        malicious = sum(1 for v in verdicts if v in ['PHISHING', 'MALICIOUS'])
        suspicious = sum(1 for v in verdicts if v == 'SUSPICIOUS')
        benign = sum(1 for v in verdicts if v == 'BENIGN')
        unknown = sum(1 for v in verdicts if v in ['UNKNOWN', 'ERROR'])
        
        risk = 'HIGH' if malicious > 0 else 'MEDIUM' if suspicious > 0 else 'LOW'
        
        return {
            'urls_found': list(urls),
            'url_analysis': results,
            'summary': {
                'total_urls': len(urls),
                'malicious': malicious,
                'suspicious': suspicious,
                'benign': benign,
                'unknown': unknown,
                'risk_level': risk,
                'message': f'Found {len(urls)} URLs. {malicious} malicious, {suspicious} suspicious, {benign} benign.'
            }
        }