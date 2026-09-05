from backend.app.services.evidence_fusion import EvidenceFusionEngine
from backend.app.intelligence.models import (
    IPIntelligenceResult,
    DomainIntelligenceResult,
    DNSIntelligenceResult,
    RedirectAnalysisResult,
    ProvenanceType,
)
from backend.app.models.investigation import AnalyzedUrl, ContentAiSummary


def test_clean_sample_invariant():
    engine = EvidenceFusionEngine()
    result = engine.fuse(
        forensic_score=0,
        forensic_anomalies=[],
        auth_status="PASSED",
        auth_results={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        origin_ip_intel=None,
        domain_intel=None,
        dns_intel=None,
        analyzed_urls=[],
        redirect_results=[],
        content_ai=ContentAiSummary(
            classification="BENIGN",
            confidence=0.0,
            intents=[],
            suspiciousPhrases=[],
            featureContributions=[]
        ),
        has_executable_attachment=False
    )
    assert result.threat_score == 0
    assert result.threat_level == "CLEAN"
    assert result.threat_type == "BENIGN"
    assert result.confidence == 0.0
    assert result.suspicious_reasons == []


def test_spoofed_sample_baseline_invariant():
    engine = EvidenceFusionEngine()
    result = engine.fuse(
        forensic_score=85,
        forensic_anomalies=["FORGED-MTA: header anomaly", "SPF-FAIL: failed SPF"],
        auth_status="FAILED",
        auth_results={"spf": "fail", "dkim": "none", "dmarc": "none"},
        origin_ip_intel=None,
        domain_intel=None,
        dns_intel=None,
        analyzed_urls=[],
        redirect_results=[],
        content_ai=ContentAiSummary(
            classification="BENIGN",
            confidence=0.0,
            intents=[],
            suspiciousPhrases=[],
            featureContributions=[]
        ),
        has_executable_attachment=False
    )
    assert result.threat_score == 85
    assert result.threat_level == "HIGH"
    assert result.threat_type == "SPOOFING"
    assert len(result.suspicious_reasons) == 2


def test_ssrf_boost_and_critical_tier():
    engine = EvidenceFusionEngine()
    ssrf_redirect = RedirectAnalysisResult(
        initial_url="http://short.ly/redirect",
        final_url="http://169.254.169.254/meta-data",
        is_ssrf_blocked=True,
        blocked_reason="Target IP is restricted: Link-local / Cloud Metadata address (169.254.169.254)",
        provenance=ProvenanceType.VERIFIED
    )
    result = engine.fuse(
        forensic_score=60,
        forensic_anomalies=["ANOMALY: test"],
        auth_status="PARTIAL",
        auth_results={"spf": "none"},
        origin_ip_intel=None,
        domain_intel=None,
        dns_intel=None,
        analyzed_urls=[],
        redirect_results=[ssrf_redirect],
        content_ai=ContentAiSummary(
            classification="BENIGN",
            confidence=0.0,
            intents=[],
            suspiciousPhrases=[],
            featureContributions=[]
        ),
        has_executable_attachment=False
    )
    # 60 + 35 = 95 -> CRITICAL
    assert result.threat_score == 95
    assert result.threat_level == "CRITICAL"
    assert any("SSRF-ATTEMPT" in r for r in result.suspicious_reasons)
