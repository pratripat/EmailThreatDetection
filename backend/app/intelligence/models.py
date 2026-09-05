"""
Data Models and Provenance Tracking for Threat Intelligence
Ensures all intelligence artifacts carry explicit provenance and never fabricate findings.
"""

from enum import Enum
from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class ProvenanceType(str, Enum):
    """
    Explicit provenance level for any intelligence attribute or finding.
    Rules out synthetic or ambiguous claims.
    """
    VERIFIED = "VERIFIED"                  # Confirmed by authoritative external service
    OBSERVED = "OBSERVED"                  # Directly parsed from email data
    HEURISTIC = "HEURISTIC"                # Derived via deterministic rules / pattern analysis
    MODEL_PREDICTION = "MODEL_PREDICTION"  # Produced by local/loaded ML inference
    NOT_CHECKED = "NOT_CHECKED"            # Deliberately skipped (e.g. non-routable IP, offline)
    UNAVAILABLE = "UNAVAILABLE"            # Service offline, timed out, or unconfigured
    ERROR = "ERROR"                        # Query attempt resulted in an error


class IPIntelligenceResult(BaseModel):
    model_config = ConfigDict(extra="ignore")

    ip: str
    abuse_score: int = Field(default=0, ge=0, le=100)
    is_whitelisted: bool = False
    total_reports: int = 0
    is_vpn: bool = False
    is_datacenter: bool = False
    is_non_routable: bool = False
    non_routable_reason: Optional[str] = None
    country_code: str = "UNKNOWN"
    country_name: Optional[str] = None
    city: Optional[str] = None
    asn: str = "UNKNOWN"
    isp: str = "UNKNOWN"
    domain: Optional[str] = None
    reputation: Literal["MALICIOUS", "SUSPICIOUS", "CLEAN", "UNKNOWN"] = "UNKNOWN"
    abuse_category: Literal["HIGH RISK", "MEDIUM RISK", "CLEAN", "NOT_CHECKED"] = "NOT_CHECKED"
    virus_total_ratio: str = "NOT_QUERIED"
    spamhaus_listed: bool = False
    provenance: ProvenanceType = ProvenanceType.NOT_CHECKED
    source: str = "local"
    error: Optional[str] = None


class DomainIntelligenceResult(BaseModel):
    model_config = ConfigDict(extra="ignore")

    domain: str
    punycode: str
    registered_age_days: int = Field(default=-1, description="-1 indicates age unknown / offline")
    creation_date: Optional[str] = None
    registrar: Optional[str] = None
    is_newly_registered: bool = False
    provenance: ProvenanceType = ProvenanceType.NOT_CHECKED
    source: str = "none"
    error: Optional[str] = None


class DNSIntelligenceResult(BaseModel):
    model_config = ConfigDict(extra="ignore")

    domain: str
    mx_records: List[str] = Field(default_factory=list)
    a_records: List[str] = Field(default_factory=list)
    txt_records: List[str] = Field(default_factory=list)
    ns_records: List[str] = Field(default_factory=list)
    spf_record: Optional[str] = None
    dmarc_record: Optional[str] = None
    dnsbl_listed: bool = False
    dnsbl_matches: List[str] = Field(default_factory=list)
    provenance: ProvenanceType = ProvenanceType.NOT_CHECKED
    error: Optional[str] = None


class URLReputationResult(BaseModel):
    model_config = ConfigDict(extra="ignore")

    url: str
    domain: str
    is_malicious: bool = False
    threat_score: int = Field(default=0, ge=0, le=100)
    engine_detections: int = 0
    total_engines: int = 0
    categories: List[str] = Field(default_factory=list)
    provenance: ProvenanceType = ProvenanceType.NOT_CHECKED
    source: str = "none"
    error: Optional[str] = None


class RedirectAnalysisResult(BaseModel):
    model_config = ConfigDict(extra="ignore")

    initial_url: str
    final_url: str
    redirect_chain: List[str] = Field(default_factory=list)
    hop_count: int = 0
    is_ssrf_blocked: bool = False
    blocked_reason: Optional[str] = None
    is_disguised_domain: bool = False
    provenance: ProvenanceType = ProvenanceType.NOT_CHECKED
    error: Optional[str] = None
