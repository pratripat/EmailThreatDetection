"""
Forensic Reporting & Summary Generation
Synthesizes header anomalies, relay hops, authentication, and origin attribution into an explainable report.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

from .parser import RelayHop


@dataclass
class ForensicReport:
    subject: str
    from_addr: str
    return_path: Optional[str]
    message_id: Optional[str]
    relay_chain: list = field(default_factory=list)
    spf_result: Optional[str] = None
    dkim_result: Optional[str] = None
    dmarc_result: Optional[str] = None
    anomalies: list = field(default_factory=list)
    earliest_ip: Optional[str] = None
    origin_label: Optional[str] = None
    origin_explanation: Optional[str] = None
    risk_score: int = 0

    selected_origin_ip: Optional[str] = None
    origin_selection_reason: Optional[str] = None
    observed_candidates: list = field(default_factory=list)
    domain_relation: Optional[str] = None
    auth_trust: str = "UNVERIFIED"
    auth_context: dict = field(default_factory=dict)
    brand_assessment: Optional[str] = None
    limitations: list = field(default_factory=list)
    origin_attribution: str = "UNVERIFIED"
    origin_attribution_reason: str = (
        "Offline .eml analysis cannot establish which Received headers were inserted "
        "by trusted infrastructure vs fabricated by the sender."
    )
    receiving_boundary: Optional[str] = None


def generate_forensic_summary(report: ForensicReport) -> str:
    """Generate a clean human-readable text summary of the forensic report."""
    lines = [
        "=== EMAIL FORENSIC REPORT ===",
        f"Subject: {report.subject}",
        f"From: {report.from_addr}",
        f"Return-Path: {report.return_path or 'N/A'}",
        f"Threat Risk Score: {report.risk_score}/100",
        f"Selected Origin IP: {report.selected_origin_ip or 'None'} ({report.origin_label or 'UNKNOWN'})",
        f"Auth Status: SPF={report.spf_result}, DKIM={report.dkim_result}, DMARC={report.dmarc_result}",
        f"Total Relay Hops: {len(report.relay_chain)}",
        f"Detected Anomalies ({len(report.anomalies)}):"
    ]
    for anom in report.anomalies:
        lines.append(f"  - {anom}")
    return "\n".join(lines)
