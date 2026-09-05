import os
import logging
from openai import OpenAI
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class GrokURLDetector:
    """Grok-powered URL detection for Email Threat Detection"""
    
    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY") or os.getenv("GROK_API_KEY") or os.getenv("XAI_API_KEY")
        if not self.api_key or self.api_key.strip().startswith("xai-example-key"):
            self.client = None
            self.enabled = False
        else:
            self.client = OpenAI(
                api_key=self.api_key.strip(),
                base_url="https://api.x.ai/v1"
            )
            self.enabled = True
        self.model = "grok-4.6"
    
    def detect(self, url: str) -> Dict[str, Any]:
        """Analyze a single URL"""
        if not self.enabled or not self.client:
            return {
                'url': url,
                'verdict': 'UNKNOWN',
                'confidence': 0.0,
                'source': 'grok_disabled',
                'error': 'Valid Grok API key not configured'
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
            
            raw_result = (response.choices[0].message.content or "").strip().upper()
            verdict = "UNKNOWN"
            for candidate in ["PHISHING", "MALICIOUS", "SUSPICIOUS", "BENIGN"]:
                if candidate in raw_result:
                    verdict = candidate
                    break

            confidence_map = {
                'BENIGN': 0.9,
                'PHISHING': 0.85,
                'MALICIOUS': 0.9,
                'SUSPICIOUS': 0.6,
                'UNKNOWN': 0.3
            }
            
            return {
                'url': url,
                'verdict': verdict,
                'confidence': confidence_map.get(verdict, 0.5),
                'source': 'grok'
            }
        except Exception as e:
            logger.warning(f"Error calling Grok API: {e}")
            return {
                'url': url,
                'verdict': 'ERROR',
                'confidence': 0.0,
                'error': str(e),
                'source': 'grok'
            }
    
    def analyze_email_urls(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Analyze multiple URLs from an email"""
        return [self.detect(url) for url in urls]