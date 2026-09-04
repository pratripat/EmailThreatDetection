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


class InvestigationService:
    def __init__(self, data_dir: str = None):
        self.data_dir = data_dir or str(DATA_DIR)
        try:
            self.origin_analyzer = OriginAnalyzer(data_dir=self.data_dir)
        except Exception:
            # OriginAnalyzer gracefully handles missing data via OriginDataError
            self.origin_analyzer = None

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
                        f"VPN-ORIGIN: selected origin IP ({selected_ip}) is known datacenter/"
                        f"hosting infrastructure ({assessment.matched_range}) — not a residential connection"
                    )
                    origin_score_contrib = 20
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

        # 5. Header Hops Mapping
        header_hops: List[HeaderHop] = []
        for idx, hop in enumerate(relay_chain, start=1):
            hop_candidates = extract_ip_candidates(hop.from_host or '')
            if not hop_candidates:
                hop_candidates = extract_ip_candidates(hop.raw or '')
            hop_ip = hop_candidates[0] if hop_candidates else "0.0.0.0"

            # Determine hop reputation matching 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'UNKNOWN'
            hop_rep: Literal["MALICIOUS", "SUSPICIOUS", "CLEAN", "UNKNOWN"] = "UNKNOWN"
            if hop_ip != "0.0.0.0" and self.origin_analyzer:
                try:
                    ass = self.origin_analyzer.assess(hop_ip)
                    if ass.is_vpn or ass.is_datacenter:
                        hop_rep = "SUSPICIOUS"
                    elif ass.is_non_global:
                        hop_rep = "UNKNOWN"
                except Exception:
                    pass

            header_hops.append(HeaderHop(
                hopNumber=idx,
                ip=hop_ip,
                hostname=hop.from_host or hop.by_host or "",
                country="UNKNOWN",
                city=None,
                asn="UNKNOWN",
                isp="UNKNOWN",
                reputation=hop_rep,
                firstSeen="UNKNOWN",
                threatFeeds=HopThreatFeeds(
                    abuseIpDb="NOT_CHECKED",
                    virusTotal="NOT_QUERIED",
                    spamhausListed=False
                )
            ))

        # 6. URL Analysis
        analyzed_urls: List[AnalyzedUrl] = []
        for u_str in parsed.embedded_urls:
            u_res = analyze_url(u_str)
            u_rep = u_res["reputation"]
            if u_rep not in ("MALICIOUS", "SUSPICIOUS", "SAFE"):
                u_rep = "UNKNOWN"
            analyzed_urls.append(AnalyzedUrl(
                url=u_res["url"],
                domain=u_res["domain"],
                registeredAgeDays=-1,  # -1 indicates unqueried WHOIS in offline mode
                reputation=u_rep,
                threatScore=u_res["threatScore"],
                flags=u_res["flags"],
                redirectChain=u_res.get("redirectChain", [])
            ))

        max_url_score = max((u.threatScore for u in analyzed_urls), default=0)

        # 7. Content Analysis
        content_res = analyze_content(parsed.subject, parsed.body_plain, parsed.body_html)
        suspicious_phrases = [
            SuspiciousPhrase(phrase=sp["phrase"], signalType=sp["signalType"])
            for sp in content_res.suspicious_phrases
        ]
        content_summary = ContentAiSummary(
            classification=content_res.classification,
            confidence=content_res.confidence,
            intents=content_res.intents,
            suspiciousPhrases=suspicious_phrases,
            featureContributions=[]  # Honest: no fabricated SHAP/LIME values
        )

        # 8. IOC Extraction
        observed_ips_list = [c['ip'] for c in observed_candidates if 'ip' in c]
        iocs_raw = extract_iocs(parsed, observed_ips_list, [u.model_dump() for u in analyzed_urls])
        iocs_summary = IocSummary(**iocs_raw)

        # 9. Multi-Vector Score Breakdown & Aggregation
        # Preserve existing header forensics score as primary deterministic signal
        overall_threat_score = forensic_score

        # Authentication sub-score
        auth_score = 0
        if auth_status == "FAILED":
            auth_score = 45
        elif auth_status == "PARTIAL":
            auth_score = 15

        breakdown = Breakdown(
            headerAnomalies=min(forensic_score, 100),
            authentication=auth_score,
            urlRisk=max_url_score,
            contentNlp=content_res.risk_score,
            senderReputation=origin_score_contrib
        )

        # 10. Centralized Threat Level & Threat Type Mapping
        # Documented centralized threshold tiers:
        # 0-14: CLEAN, 15-39: LOW, 40-69: SUSPICIOUS, 70-89: HIGH, 90-100: CRITICAL
        if overall_threat_score >= 90:
            threat_level = "CRITICAL"
        elif overall_threat_score >= 70:
            threat_level = "HIGH"
        elif overall_threat_score >= 40:
            threat_level = "SUSPICIOUS"
        elif overall_threat_score >= 15:
            threat_level = "LOW"
        else:
            threat_level = "CLEAN"

        # Threat Type classification based on evidenced indicators
        has_executable_attachment = any(
            att.filename.lower().endswith(('.exe', '.scr', '.vbs', '.js', '.iso', '.bat'))
            for att in parsed.attachments
        )

        if has_executable_attachment:
            threat_type = "MALWARE_DROP"
        elif "Credential Harvesting" in content_res.intents or max_url_score >= 60:
            threat_type = "PHISHING" if overall_threat_score >= 40 else "BENIGN"
        elif "Executive Impersonation" in content_res.intents or "Financial Solicitation" in content_res.intents:
            threat_type = "BEC_FRAUD" if overall_threat_score >= 40 else "BENIGN"
        elif overall_threat_score >= 40:
            threat_type = "SPOOFING"
        else:
            threat_type = "BENIGN"

        # 11. Attack Graph Construction
        graph_raw = build_attack_graph(
            subject=parsed.subject,
            sender_domain=from_domain,
            origin_ip=selected_ip,
            relay_hops=[h.model_dump() for h in header_hops],
            analyzed_urls=[u.model_dump() for u in analyzed_urls],
            detected_intents=content_res.intents,
            threat_score=overall_threat_score,
            auth_status=auth_status,
        )
        attack_graph = AttackGraph(
            nodes=[AttackGraphNode(**n) for n in graph_raw["nodes"]],
            edges=[AttackGraphEdge(**e) for e in graph_raw["edges"]]
        )

        # 12. Suspicious Reasons Generation
        suspicious_reasons: List[str] = list(anomalies)

        # Include prominent URL flags if URLs are elevated risk
        if max_url_score >= 60:
            for u in analyzed_urls:
                if u.threatScore >= 60:
                    suspicious_reasons.append(
                        f"Embedded URL '{u.url}' flagged as {u.reputation}: {', '.join(u.flags)}"
                    )

        # Include social engineering intent reasons
        if content_res.intents:
            suspicious_reasons.append(
                f"Email body exhibits social engineering indicators: {', '.join(content_res.intents)}"
            )

        # 13. Overall Confidence (Task 4: honest representation without fabricated ML probability)
        overall_confidence = 0.0

        return InvestigationData(
            id=investigation_id,
            subject=subject_str,
            from_=from_str,
            to=to_str,
            receivedDate=received_date_str,
            threatScore=overall_threat_score,
            threatLevel=threat_level,
            threatType=threat_type,
            confidence=overall_confidence,
            authStatus=auth_status,
            breakdown=breakdown,
            suspiciousReasons=suspicious_reasons,
            headerHops=header_hops,
            authentication=authentication_summary,
            urls=analyzed_urls,
            contentAi=content_summary,
            iocs=iocs_summary,
            attackGraph=attack_graph,
            rawHeaders=parsed.raw_headers_str or None,
            rawBody=parsed.raw_body_str or (parsed.body_plain or parsed.body_html or None)
        )
