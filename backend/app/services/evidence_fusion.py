"""
Evidence Fusion Engine
Synthesizes deterministic header forensics, dual-stack origin analysis, external threat
intelligence (IP, domain, DNS, URL reputation), SSRF inspection, and NLP content classifications
into a mathematically explainable threat score and auditable investigation summary.
Strictly preserves baseline regression invariants while incorporating verified intelligence.
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Literal

from ..models.investigation import (
    Breakdown,
    AnalyzedUrl,
    ContentAiSummary,
)
from ..intelligence.models import (
    IPIntelligenceResult,
    DomainIntelligenceResult,
    DNSIntelligenceResult,
    URLReputationResult,
    RedirectAnalysisResult,
    ProvenanceType,
)

logger = logging.getLogger(__name__)


@dataclass
class FusionAuditEntry:
    category: str
    weight: int
    rule: str
    provenance: str


@dataclass
class FusionResult:
    threat_score: int
    threat_level: Literal["CRITICAL", "HIGH", "SUSPICIOUS", "LOW", "CLEAN"]
    threat_type: str
    confidence: float
    breakdown: Breakdown
    suspicious_reasons: List[str]
    audit_log: List[FusionAuditEntry] = field(default_factory=list)


class EvidenceFusionEngine:
    """
    Multivariate Evidence Fusion Engine.
    Combines multi-stream intelligence with rigorous invariant checks.
    """

    def fuse(
        self,
        forensic_score: int,
        forensic_anomalies: List[str],
        auth_status: Literal["FAILED", "PASSED", "PARTIAL"],
        auth_results: Dict[str, Any],
        origin_score_contrib: int = 0,
        content_risk_score: int = 0,
        origin_ip_intel: Optional[IPIntelligenceResult] = None,
        domain_intel: Optional[DomainIntelligenceResult] = None,
        dns_intel: Optional[DNSIntelligenceResult] = None,
        analyzed_urls: Optional[List[AnalyzedUrl]] = None,
        redirect_results: Optional[List[RedirectAnalysisResult]] = None,
        content_ai: Optional[ContentAiSummary] = None,
        has_executable_attachment: bool = False,
    ) -> FusionResult:
        audit_log: List[FusionAuditEntry] = []
        suspicious_reasons: List[str] = list(forensic_anomalies)
        analyzed_urls = analyzed_urls or []
        redirect_results = redirect_results or []

        # 1. Base Score from Deterministic Header Forensics (V2.6 baseline anchor)
        score = int(forensic_score)
        if score > 0:
            audit_log.append(FusionAuditEntry(
                category="header_forensics",
                weight=score,
                rule="Base deterministic header forensics score",
                provenance="HEURISTIC",
            ))

        # 2. Append URL warnings (preserving baseline suspiciousReasons structure)
        max_url_risk = max((u.threatScore for u in analyzed_urls), default=0)
        has_malicious_url = any(u.reputation == "MALICIOUS" for u in analyzed_urls)
        if max_url_risk >= 60:
            for u in analyzed_urls:
                if u.threatScore >= 60:
                    suspicious_reasons.append(
                        f"Embedded URL '{u.url}' flagged as {u.reputation}: {', '.join(u.flags)}"
                    )

        # 3. Append Content AI / Social Engineering warnings
        if content_ai and content_ai.intents:
            suspicious_reasons.append(
                f"Email body exhibits social engineering indicators: {', '.join(content_ai.intents)}"
            )

        # 4. External Verified Intelligence Adjustments
        # Only verified external signals or SSRF blocks boost the score beyond the deterministic baseline
        sender_rep_add = 0
        if origin_ip_intel and not origin_ip_intel.is_non_routable:
            # Verified high abuse score from external feeds (AbuseIPDB / VT)
            if origin_ip_intel.provenance == ProvenanceType.VERIFIED:
                if origin_ip_intel.abuse_score >= 80:
                    boost = 15
                    score = min(100, score + boost)
                    sender_rep_add += boost
                    suspicious_reasons.append(
                        f"ORIGIN-THREAT-FEED: origin IP {origin_ip_intel.ip} has critical abuse score "
                        f"({origin_ip_intel.abuse_score}%) reported by AbuseIPDB"
                    )
                    audit_log.append(FusionAuditEntry(
                        category="ip_intelligence",
                        weight=boost,
                        rule="Verified critical IP abuse score",
                        provenance="VERIFIED",
                    ))
                elif origin_ip_intel.abuse_score >= 40:
                    boost = 10
                    score = min(100, score + boost)
                    sender_rep_add += boost
                    suspicious_reasons.append(
                        f"ORIGIN-THREAT-FEED: origin IP {origin_ip_intel.ip} has elevated abuse reports "
                        f"({origin_ip_intel.abuse_score}%)"
                    )
                    audit_log.append(FusionAuditEntry(
                        category="ip_intelligence",
                        weight=boost,
                        rule="Verified moderate IP abuse score",
                        provenance="VERIFIED",
                    ))

            # DNSBL Listing
            if origin_ip_intel.spamhaus_listed:
                boost = 15
                score = min(100, score + boost)
                sender_rep_add += boost
                suspicious_reasons.append(
                    f"ORIGIN-DNSBL: origin IP {origin_ip_intel.ip} is listed on Spamhaus/DNSBL"
                )
                audit_log.append(FusionAuditEntry(
                    category="dnsbl",
                    weight=boost,
                    rule="IP listed on DNSBL blacklist",
                    provenance="VERIFIED",
                ))

        # 5. Domain Age & Registration Fusion
        if domain_intel and domain_intel.provenance == ProvenanceType.VERIFIED:
            if domain_intel.is_newly_registered and auth_status != "PASSED":
                boost = 15
                score = min(100, score + boost)
                suspicious_reasons.append(
                    f"NEW-DOMAIN: sender domain '{domain_intel.domain}' was registered {domain_intel.registered_age_days} "
                    f"days ago (< 30 days) — high indicator for throwaway phishing infrastructure"
                )
                audit_log.append(FusionAuditEntry(
                    category="domain_intelligence",
                    weight=boost,
                    rule="Newly registered domain with unverified/failing authentication",
                    provenance="VERIFIED",
                ))

        # 6. SSRF blocks & Disguised Redirects
        for red in redirect_results:
            if red.is_ssrf_blocked:
                score = max(score, 95)
                suspicious_reasons.append(
                    f"SSRF-ATTEMPT: embedded redirect target attempted access to restricted infrastructure: {red.blocked_reason}"
                )
                audit_log.append(FusionAuditEntry(
                    category="url_redirect",
                    weight=35,
                    rule="Redirect chain blocked by SSRF defense",
                    provenance="VERIFIED",
                ))
            elif red.is_disguised_domain and score >= 30:
                suspicious_reasons.append(
                    f"DISGUISED-REDIRECT: initial URL domain does not match final destination ({red.final_url})"
                )
                audit_log.append(FusionAuditEntry(
                    category="url_redirect",
                    weight=10,
                    rule="Disguised domain open-redirect chain",
                    provenance="OBSERVED",
                ))

        # 7. Attachment Fusion
        if has_executable_attachment:
            score = max(score, 90)
            suspicious_reasons.append(
                "MALWARE-ATTACHMENT: email contains high-risk executable payload attachment"
            )
            audit_log.append(FusionAuditEntry(
                category="attachment",
                weight=50,
                rule="Executable payload attachment detected",
                provenance="OBSERVED",
            ))

        # 8. Clean Email Invariant:
        # If base forensic score is 0 and no external verified indicators fired, threat score is 0
        if forensic_score == 0 and not any(a.provenance == "VERIFIED" for a in audit_log if a.weight > 0):
            score = 0
            suspicious_reasons = []

        final_threat_score = max(0, min(100, score))

        # 9. Compute Breakdown Sub-Scores
        auth_score = 45 if auth_status == "FAILED" else (15 if auth_status == "PARTIAL" else 0)
        sender_rep_score = min(100, origin_score_contrib + sender_rep_add)

        breakdown = Breakdown(
            headerAnomalies=min(100, forensic_score),
            authentication=auth_score,
            urlRisk=max_url_risk,
            contentNlp=content_risk_score,
            senderReputation=sender_rep_score,
        )

        # 10. Centralized Threat Level Tiers
        # CRITICAL: 90-100, HIGH: 70-89, SUSPICIOUS: 40-69, LOW: 15-39, CLEAN: 0-14
        if final_threat_score >= 90:
            threat_level = "CRITICAL"
        elif final_threat_score >= 70:
            threat_level = "HIGH"
        elif final_threat_score >= 40:
            threat_level = "SUSPICIOUS"
        elif final_threat_score >= 15:
            threat_level = "LOW"
        else:
            threat_level = "CLEAN"

        # 11. Threat Type Classification
        if has_executable_attachment:
            threat_type = "MALWARE_DROP"
        elif "Credential Harvesting" in content_ai.intents or max_url_risk >= 60:
            threat_type = "PHISHING" if final_threat_score >= 40 else "BENIGN"
        elif "Executive Impersonation" in content_ai.intents or "Financial Solicitation" in content_ai.intents:
            threat_type = "BEC_FRAUD" if final_threat_score >= 40 else "BENIGN"
        elif final_threat_score >= 40:
            threat_type = "SPOOFING"
        else:
            threat_type = "BENIGN"

        # 12. Investigation Confidence
        # Honest representation: 0.0 for clean/unverified heuristic
        verified_count = sum(1 for a in audit_log if a.provenance == "VERIFIED")
        if final_threat_score == 0:
            confidence = 0.0
        elif verified_count >= 2:
            confidence = 0.90
        elif verified_count == 1:
            confidence = 0.75
        else:
            confidence = 0.0  # Baseline honest heuristic confidence when purely local

        return FusionResult(
            threat_score=final_threat_score,
            threat_level=threat_level,
            threat_type=threat_type,
            confidence=confidence,
            breakdown=breakdown,
            suspicious_reasons=suspicious_reasons,
            audit_log=audit_log,
        )
