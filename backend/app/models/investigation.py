"""
Canonical Pydantic Data Models for Email Investigation
Strictly implements the frontend's InvestigationData JSON contract.
"""

from typing import List, Optional, Dict, Any, Union, Literal
from pydantic import BaseModel, Field, ConfigDict


class HopThreatFeeds(BaseModel):
    model_config = ConfigDict(extra="ignore")

    abuseIpDb: Literal["HIGH RISK", "MEDIUM RISK", "CLEAN", "NOT_CHECKED"] = Field(
        default="NOT_CHECKED",
        description="AbuseIPDB reputation result or safe NOT_CHECKED fallback for offline analysis"
    )
    virusTotal: str = Field(
        default="NOT_QUERIED",
        description="VirusTotal detection ratio or safe NOT_QUERIED fallback"
    )
    spamhausListed: bool = Field(
        default=False,
        description="Spamhaus listing flag (false when unlisted or offline)"
    )


class HeaderHop(BaseModel):
    model_config = ConfigDict(extra="ignore")

    hopNumber: int = Field(..., description="1-indexed sequence position in relay chain")
    ip: str = Field(..., description="Observed relay IP candidate")
    hostname: str = Field(default="", description="Host identifier from Received header")
    country: str = Field(default="UNKNOWN", description="ISO country code or UNKNOWN (V3 Geolocation pending)")
    city: Optional[str] = Field(default=None, description="City name (V3 Geolocation pending)")
    asn: str = Field(default="UNKNOWN", description="Autonomous System Number or UNKNOWN (V3 ASN pending)")
    isp: str = Field(default="UNKNOWN", description="Internet Service Provider or UNKNOWN (V3 ASN pending)")
    reputation: Literal["MALICIOUS", "SUSPICIOUS", "CLEAN", "UNKNOWN"] = Field(
        default="UNKNOWN",
        description="Hop reputation classification"
    )
    firstSeen: str = Field(default="UNKNOWN", description="First seen timestamp or UNKNOWN (V3 Threat Intel pending)")
    threatFeeds: HopThreatFeeds = Field(default_factory=HopThreatFeeds, description="External threat feed records")

class AuthenticationSummary(BaseModel):
    model_config = ConfigDict(extra="ignore")

    spf: Literal["PASSED", "FAILED", "SOFTFAIL", "NONE"]
    dkim: Literal["PASSED", "FAILED", "NONE"]
    dmarc: Literal["PASSED", "FAILED", "NONE"]
    fromDomain: str
    returnPathDomain: str = Field(default="", description="Return-Path domain or empty string if absent")
    alignmentMatched: bool
    notes: List[str] = Field(default_factory=list)


class GrokAnalysis(BaseModel):
    """Grok AI analysis results for a URL"""
    model_config = ConfigDict(extra="ignore")
    
    verdict: Literal["BENIGN", "PHISHING", "MALICIOUS", "SUSPICIOUS", "UNKNOWN"] = Field(
        default="UNKNOWN",
        description="Grok's AI verdict on the URL"
    )
    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Grok's confidence in its verdict (0-1)"
    )
    reason: Optional[str] = Field(
        default=None,
        description="Grok's reasoning for the verdict"
    )


class AnalyzedUrl(BaseModel):
    model_config = ConfigDict(extra="ignore")

    url: str
    domain: str
    registeredAgeDays: Optional[int] = Field(default=-1, description="Domain age in days (-1 or null = unqueried WHOIS in offline mode)")
    reputation: Literal["MALICIOUS", "SUSPICIOUS", "SAFE", "UNKNOWN"] = Field(
        default="UNKNOWN",
        description="Reputation verdict"
    )
    threatScore: int = Field(..., ge=0, le=100)
    flags: List[str] = Field(default_factory=list)
    redirectChain: Optional[List[str]] = Field(default_factory=list)
    grok_analysis: Optional[GrokAnalysis] = Field(
        default=None,
        description="Grok AI analysis results (null if Grok is disabled or failed)"
    )


class SuspiciousPhrase(BaseModel):
    model_config = ConfigDict(extra="ignore")

    phrase: str
    signalType: Literal["Urgency signal", "Credential request", "Financial coercion", "Security impersonation"]


class FeatureContribution(BaseModel):
    model_config = ConfigDict(extra="ignore")

    feature: str
    weight: float
    impact: Literal["positive", "negative"]


class ContentAiSummary(BaseModel):
    model_config = ConfigDict(extra="ignore")

    classification: Literal["PHISHING", "SPOOFING", "BEC_FRAUD", "BENIGN", "MALWARE_DROP"] = Field(
        ...,
        description="High-level category matching frontend classification enum"
    )
    confidence: float = Field(..., ge=0.0, le=1.0, description="Honest heuristic confidence (no synthetic ML percentages)")
    intents: List[str] = Field(default_factory=list)
    suspiciousPhrases: List[SuspiciousPhrase] = Field(default_factory=list)
    featureContributions: List[FeatureContribution] = Field(default_factory=list)


class IocSummary(BaseModel):
    model_config = ConfigDict(extra="ignore")

    ipAddresses: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    emailAddresses: List[str] = Field(default_factory=list)
    hashes: List[str] = Field(default_factory=list)


class AttackGraphNode(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    label: str
    sublabel: str = Field(default="", description="Descriptive sublabel for UI node")
    type: Literal["email", "domain", "ip", "page", "action"]
    status: Literal["critical", "warning", "clean", "neutral"]


class AttackGraphEdge(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    from_: str = Field(..., alias="from")
    to: str
    label: Optional[str] = None


class AttackGraph(BaseModel):
    model_config = ConfigDict(extra="ignore")

    nodes: List[AttackGraphNode] = Field(default_factory=list)
    edges: List[AttackGraphEdge] = Field(default_factory=list)


class Breakdown(BaseModel):
    model_config = ConfigDict(extra="ignore")

    headerAnomalies: int = Field(..., ge=0, le=100)
    authentication: int = Field(..., ge=0, le=100)
    urlRisk: int = Field(..., ge=0, le=100)
    contentNlp: int = Field(..., ge=0, le=100)
    senderReputation: int = Field(..., ge=0, le=100)


class InvestigationData(BaseModel):
    """
    Authoritative Investigation Response Model matching the frontend InvestigationData TypeScript interface exactly.
    """
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    id: str = Field(..., description="Unique investigation identifier (UUIDv4)")
    subject: str = Field(..., description="Email subject or empty string")
    from_: str = Field(..., alias="from", description="From address or empty string")
    to: str = Field(..., description="Recipient address or empty string")
    receivedDate: str = Field(..., description="RFC 5322 date or empty string")
    threatScore: int = Field(..., ge=0, le=100, description="Aggregated threat risk score (0-100)")
    threatLevel: Literal["CRITICAL", "HIGH", "SUSPICIOUS", "LOW", "CLEAN"]
    threatType: str = Field(..., description="High-level threat category string")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Investigation confidence score")
    authStatus: Literal["FAILED", "PASSED", "PARTIAL"]
    breakdown: Breakdown
    suspiciousReasons: List[str] = Field(default_factory=list)
    headerHops: List[HeaderHop] = Field(default_factory=list)
    authentication: AuthenticationSummary
    urls: List[AnalyzedUrl] = Field(default_factory=list)
    contentAi: ContentAiSummary
    iocs: IocSummary
    attackGraph: AttackGraph
    rawHeaders: Optional[str] = None
    rawBody: Optional[str] = None
