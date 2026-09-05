"""
Investigation Orchestrator Service
Coordinates the end-to-end multi-analyzer email threat investigation pipeline:
1. MIME / Header Parsing
2. Header Forensics & Relay Path Reconstruction
3. Dual-Stack Origin IP Intelligence
4. Deterministic URL Extraction & Typosquatting Analysis
5. Baseline Content NLP / Social Engineering Inspection
6. Normalized IOC Extraction
7. Evidence-Backed Attack Graph Construction
8. Multi-Vector Score Aggregation & Canonical InvestigationData Synthesis
"""

import uuid
import email.utils
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Union

from ..config import DATA_DIR
from ..analyzers.mime_analysis import parse_email_bytes, ParsedEmail
from ..analyzers.header_forensics import (
    parse_received_header,
    parse_auth_context,
    detect_anomalies,
    select_origin_ip,
    compute_risk_score,
    extract_ip_candidates,
    DomainRelation,
    domain_relationship,
)
from ..analyzers.origin_analysis import OriginAnalyzer, OriginDataError, classify_ip_type
from ..analyzers.url_analysis import analyze_url
from ..analyzers.content_analysis import analyze_content
from ..analyzers.ioc_extraction import extract_iocs
from ..analyzers.attack_graph import build_attack_graph
from ..models.investigation import (
    InvestigationData,
    Breakdown,
    HeaderHop,
    HopThreatFeeds,
    AuthenticationSummary,
    AnalyzedUrl,
    SuspiciousPhrase,
    FeatureContribution,
    ContentAiSummary,
    IocSummary,
    AttackGraph,
    AttackGraphNode,
    AttackGraphEdge,
)
from ..intelligence.ip_reputation import IPReputationService
from ..intelligence.domain_intelligence import DomainIntelligenceService
from ..intelligence.dns_intelligence import DNSIntelligenceService
from ..intelligence.url_reputation import URLReputationService
from ..intelligence.redirect_analyzer import RedirectAnalyzer
from ..intelligence.models import ProvenanceType, RedirectAnalysisResult
from ..ml.content_classifier import ContentClassifierService
from .evidence_fusion import EvidenceFusionEngine


class InvestigationService:
    def __init__(self, data_dir: str = None):
        self.data_dir = data_dir or str(DATA_DIR)
        try:
            self.origin_analyzer = OriginAnalyzer(data_dir=self.data_dir)
        except Exception:
            # OriginAnalyzer gracefully handles missing data via OriginDataError
            self.origin_analyzer = None

        self.ip_intel_service = IPReputationService(origin_analyzer=self.origin_analyzer)
        self.domain_intel_service = DomainIntelligenceService()
        self.dns_intel_service = DNSIntelligenceService()
        self.url_intel_service = URLReputationService()
        self.redirect_analyzer = RedirectAnalyzer()
        self.content_classifier = ContentClassifierService()
        self.fusion_engine = EvidenceFusionEngine()

    def analyze_email(self, eml_bytes: bytes, filename: Optional[str] = None) -> InvestigationData:
        """
        Execute the complete deterministic investigation pipeline on raw email bytes.
        Returns a canonical InvestigationData object matching the authoritative frontend contract.
        """
        investigation_id = str(uuid.uuid4())

        # 1. MIME & Header Parsing
        parsed = parse_email_bytes(eml_bytes)

        # Sender & Recipient addresses: empty string if not present
        from_display, from_email = email.utils.parseaddr(parsed.from_addr)
        from_domain = from_email.split('@')[-1].lower() if '@' in from_email else ""

        _, return_email = email.utils.parseaddr(parsed.return_path or '')
        return_domain = return_email.split('@')[-1].lower() if '@' in return_email else ""

        # Top-level RFC 5322 metadata: strictly empty string when header genuinely does not exist
        subject_str = parsed.subject
        from_str = parsed.from_addr
        to_str = parsed.to_addr
        received_date_str = parsed.date_str

        # 2. Header Forensics & Relay Path Reconstruction
        relay_chain = [parse_received_header(h) for h in parsed.received_headers]

        # Receiving Boundary MTA
        receiving_boundary = relay_chain[0].by_host if relay_chain else None

        # Authentication Context
        auth_ctx = parse_auth_context(parsed.raw_message, relay_chain, from_domain=from_domain)
        auth_results = auth_ctx['mechanisms']

        # Header Anomalies & Domain Relationship
        anomalies, domain_rel_str, brand_cat = detect_anomalies(parsed.raw_message, relay_chain, auth_results)

        # Origin IP Candidate Selection
        selected_ip, selection_reason, observed_candidates = select_origin_ip(relay_chain)

        # 3. Origin IP Intelligence Assessment
        origin_label = "UNKNOWN"
        origin_score_contrib = 0
        if selected_ip and self.origin_analyzer:
            try:
                assessment = self.origin_analyzer.assess(selected_ip)
                origin_label = assessment.confidence_label
                if assessment.is_vpn:
                    anomalies.append(
                        f"VPN-ORIGIN: selected origin IP ({selected_ip}) is a known VPN "
                        f"exit node ({assessment.matched_range}) — true origin obscured"
                    )
                    origin_score_contrib = 20
                elif assessment.is_datacenter:
                    anomalies.append(
                        f"DATACENTER-ORIGIN: selected origin IP ({selected_ip}) belongs to known "
                        f"datacenter/email-service/hosting infrastructure ({assessment.matched_range})."
                    )
                    origin_score_contrib = 0
                elif assessment.is_non_global:
                    anomalies.append(
                        f"NON-ROUTABLE-ORIGIN: selected origin IP ({selected_ip}) is "
                        f"{assessment.non_global_reason} — should never appear in a legitimate relay chain"
                    )
                    origin_score_contrib = 15
            except OriginDataError:
                origin_label = "UNAVAILABLE"
        elif not selected_ip and observed_candidates:
            anomalies.append(
                f"NON-ROUTABLE-ORIGIN: no publicly routable origin IP found in relay chain; "
                f"observed candidates are internal/private: {', '.join(c['ip'] for c in observed_candidates)}"
            )

        # Compute Header Forensics Risk Score
        forensic_score = compute_risk_score(anomalies, auth_results)

        # 4. Authentication Response Mapping
        def map_spf(val: Optional[str]) -> str:
            if val == 'pass': return "PASSED"
            if val == 'fail': return "FAILED"
            if val == 'softfail': return "SOFTFAIL"
            return "NONE"

        def map_dkim_dmarc(val: Optional[str]) -> str:
            if val == 'pass': return "PASSED"
            if val == 'fail': return "FAILED"
            return "NONE"

        spf_mapped = map_spf(auth_results.get('spf'))
        dkim_mapped = map_dkim_dmarc(auth_results.get('dkim'))
        dmarc_mapped = map_dkim_dmarc(auth_results.get('dmarc'))

        # Alignment matched
        alignment_matched = False
        if from_domain and return_domain:
            rel = domain_relationship(from_domain, return_domain)
            alignment_matched = rel in (
                DomainRelation.EXACT_MATCH,
                DomainRelation.SUBDOMAIN_RELATION,
                DomainRelation.SAME_REGISTRABLE_DOMAIN
            )

        # Task 7: Overall authStatus mapping
        # PASSED = authentication evidence is clean/passing
        # FAILED = meaningful authentication failure
        # PARTIAL = mixed/pass-but-unverified/missing combination
        auth_notes = list(auth_ctx.get('notes', []))
        if spf_mapped == "FAILED" or dkim_mapped == "FAILED" or dmarc_mapped == "FAILED":
            auth_status = "FAILED"
        elif any("authserv id (" in n.lower() and "does not match top receiving mta" in n.lower() for n in auth_notes):
            # Claimed pass from an untrusted / forged boundary MTA
            auth_status = "PARTIAL"
        elif spf_mapped == "PASSED" and (dkim_mapped == "PASSED" or dmarc_mapped == "PASSED"):
            auth_status = "PASSED"
        else:
            auth_status = "PARTIAL"

        authentication_summary = AuthenticationSummary(
            spf=spf_mapped,
            dkim=dkim_mapped,
            dmarc=dmarc_mapped,
            fromDomain=from_domain,
            returnPathDomain=return_domain,
            alignmentMatched=alignment_matched,
            notes=auth_notes
        )

        # 5. Header Hops Mapping with IP Intelligence
        header_hops: List[HeaderHop] = []
        for idx, hop in enumerate(relay_chain, start=1):
            hop_candidates = extract_ip_candidates(hop.from_host or '')
            if not hop_candidates:
                hop_candidates = extract_ip_candidates(hop.raw or '')
            hop_ip = hop_candidates[0] if hop_candidates else "0.0.0.0"

            # Query IP Intelligence
            ip_intel = self.ip_intel_service.lookup(hop_ip)

            header_hops.append(HeaderHop(
                hopNumber=idx,
                ip=hop_ip,
                hostname=hop.from_host or hop.by_host or "",
                country=ip_intel.country_code,
                city=ip_intel.city,
                asn=ip_intel.asn,
                isp=ip_intel.isp,
                reputation=ip_intel.reputation,
                firstSeen="UNKNOWN",
                threatFeeds=HopThreatFeeds(
                    abuseIpDb=ip_intel.abuse_category,
                    virusTotal=ip_intel.virus_total_ratio,
                    spamhausListed=ip_intel.spamhaus_listed
                )
            ))

        # 6. URL Analysis & SSRF-Safe Redirect Inspection
        analyzed_urls: List[AnalyzedUrl] = []
        redirect_results: List[RedirectAnalysisResult] = []
        for u_str in parsed.embedded_urls:
            u_res = analyze_url(u_str)
            u_intel = self.url_intel_service.lookup(u_str)
            red_res = self.redirect_analyzer.trace_redirects(u_str)
            redirect_results.append(red_res)

            dom_url = u_res.get("domain", "")
            dom_intel = self.domain_intel_service.lookup(dom_url) if dom_url else None
            registered_age = dom_intel.registered_age_days if dom_intel else -1

            u_rep = u_intel.reputation if u_intel.provenance == ProvenanceType.VERIFIED else u_res["reputation"]
            if u_rep not in ("MALICIOUS", "SUSPICIOUS", "SAFE"):
                u_rep = "UNKNOWN"

            flags = list(dict.fromkeys(u_res["flags"] + u_intel.categories))
            if red_res.is_ssrf_blocked:
                flags.append("SSRF Attempt Blocked")
            if red_res.is_disguised_domain:
                flags.append("Disguised Redirect Domain")

            threat_score = max(u_res["threatScore"], u_intel.threat_score)
            if red_res.is_ssrf_blocked:
                threat_score = max(threat_score, 90)

            analyzed_urls.append(AnalyzedUrl(
                url=u_res["url"],
                domain=u_res["domain"],
                registeredAgeDays=registered_age,
                reputation=u_rep,
                threatScore=threat_score,
                flags=flags,
                redirectChain=red_res.redirect_chain if red_res.redirect_chain else u_res.get("redirectChain", [])
            ))

        # 7. Content Analysis & ML Classifier
        content_summary = self.content_classifier.classify(
            parsed.subject, parsed.body_plain, parsed.body_html
        )
        content_risk = 0
        if "Urgent Coercion" in content_summary.intents:
            content_risk += 35
        if "Credential Harvesting" in content_summary.intents:
            content_risk += 45
        if "Financial Solicitation" in content_summary.intents:
            content_risk += 30
        if "Executive Impersonation" in content_summary.intents:
            content_risk += 30
        content_risk_score = min(content_risk, 100)

        # 8. IOC Extraction
        observed_ips_list = [c['ip'] for c in observed_candidates if 'ip' in c]
        iocs_raw = extract_iocs(parsed, observed_ips_list, [u.model_dump() for u in analyzed_urls])
        iocs_summary = IocSummary(**iocs_raw)

        # 9. Attachment Inspection
        has_executable_attachment = any(
            att.filename.lower().endswith(('.exe', '.scr', '.vbs', '.js', '.iso', '.bat'))
            for att in parsed.attachments
        )

        # 10. Multi-Stream Threat Intelligence Lookups
        origin_ip_intel = self.ip_intel_service.lookup(selected_ip) if selected_ip else None
        sender_domain_intel = self.domain_intel_service.lookup(from_domain) if from_domain else None
        sender_dns_intel = self.dns_intel_service.resolve_domain(from_domain) if from_domain else None

        # 11. Evidence Fusion
        fusion_res = self.fusion_engine.fuse(
            forensic_score=forensic_score,
            forensic_anomalies=anomalies,
            auth_status=auth_status,
            auth_results=auth_results,
            origin_score_contrib=origin_score_contrib,
            content_risk_score=content_risk_score,
            origin_ip_intel=origin_ip_intel,
            domain_intel=sender_domain_intel,
            dns_intel=sender_dns_intel,
            analyzed_urls=analyzed_urls,
            redirect_results=redirect_results,
            content_ai=content_summary,
            has_executable_attachment=has_executable_attachment,
        )

        # 12. Attack Graph Construction
        graph_raw = build_attack_graph(
            subject=parsed.subject,
            sender_domain=from_domain,
            origin_ip=selected_ip,
            relay_hops=[h.model_dump() for h in header_hops],
            analyzed_urls=[u.model_dump() for u in analyzed_urls],
            detected_intents=content_summary.intents,
            threat_score=fusion_res.threat_score,
            auth_status=auth_status,
        )
        attack_graph = AttackGraph(
            nodes=[AttackGraphNode(**n) for n in graph_raw["nodes"]],
            edges=[AttackGraphEdge(**e) for e in graph_raw["edges"]]
        )

        return InvestigationData(
            id=investigation_id,
            subject=subject_str,
            from_=from_str,
            to=to_str,
            receivedDate=received_date_str,
            threatScore=fusion_res.threat_score,
            threatLevel=fusion_res.threat_level,
            threatType=fusion_res.threat_type,
            confidence=fusion_res.confidence,
            authStatus=auth_status,
            breakdown=fusion_res.breakdown,
            suspiciousReasons=fusion_res.suspicious_reasons,
            headerHops=header_hops,
            authentication=authentication_summary,
            urls=analyzed_urls,
            contentAi=content_summary,
            iocs=iocs_summary,
            attackGraph=attack_graph,
            rawHeaders=parsed.raw_headers_str or None,
            rawBody=parsed.raw_body_str or (parsed.body_plain or parsed.body_html or None)
        )
