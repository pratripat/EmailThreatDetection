"""
Pydantic Request & Response Schemas
Type-safe schemas for email forensics and Grok-powered URL threat analysis.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class CheckUrlRequest(BaseModel):
    url: str = Field(..., description="Target URL to inspect", example="https://paypa1-security-verify.com/login")


class GrokAnalysisSchema(BaseModel):
    verdict: str = Field(..., description="BENIGN, PHISHING, MALICIOUS, or SUSPICIOUS")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score from 0.0 to 1.0")
    reason: str = Field(..., description="Technical justification for verdict")


class AnalyzedUrlSchema(BaseModel):
    url: str
    domain: str
    reputation: str
    threatScore: int = Field(..., ge=0, le=100)
    flags: List[str]
    grok_analysis: Optional[GrokAnalysisSchema] = None
    cached: Optional[bool] = False


class AnalyzeEmailResponse(BaseModel):
    final_threat_score: int = Field(..., ge=0, le=100)
    threat_tier: str = Field(..., description="CRITICAL, HIGH, SUSPICIOUS, or LOW")
    confidence: float = Field(..., ge=0.0, le=1.0)
    primary_threat_vector: str
    component_scores: Dict[str, int]
    key_indicators: List[str]
    recommendation: str
    header_forensics: Dict[str, Any]
    origin_analysis: Dict[str, Any]
    url_analysis: Dict[str, Any]
