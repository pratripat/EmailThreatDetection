from typing import Dict, Any
from .grok_client import GrokURLDetector
from .email_extractor import EmailURLExtractor

class URLThreatIntegration:
    """Integrate URL detection with existing threat detection"""
    
    def __init__(self):
        self.detector = GrokURLDetector()
        self.extractor = EmailURLExtractor()
    
    def analyze_email(self, eml_content: str) -> Dict[str, Any]:
        """Analyze all URLs in an email"""
        # Extract URLs
        urls = self.extractor.extract_from_eml(eml_content)
        
        # If no URLs found
        if not urls:
            return {
                'urls_found': [],
                'url_analysis': [],
                'summary': 'No URLs found in email'
            }
        
        # Analyze each URL
        results = self.detector.analyze_email_urls(list(urls))
        
        # Summarize
        verdicts = [r.get('verdict', 'UNKNOWN') for r in results]
        malicious = sum(1 for v in verdicts if v in ['PHISHING', 'MALICIOUS'])
        suspicious = sum(1 for v in verdicts if v == 'SUSPICIOUS')
        benign = sum(1 for v in verdicts if v == 'BENIGN')
        
        return {
            'urls_found': list(urls),
            'url_analysis': results,
            'summary': {
                'total_urls': len(urls),
                'malicious': malicious,
                'suspicious': suspicious,
                'benign': benign,
                'risk_level': 'HIGH' if malicious > 0 else 'MEDIUM' if suspicious > 0 else 'LOW'
            }
        }