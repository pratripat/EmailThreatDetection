"""
Analysis Routes
Endpoints for full email forensic investigation and isolated Grok AI URL threat analysis.
"""

import email
import logging
from typing import Optional, Dict, Any
from email.message import Message

from fastapi import APIRouter, File, UploadFile, Form, HTTPException, status, Request
from pydantic import BaseModel

from src.header_forensics.parser import parse_received_header, extract_ip_candidates, RelayHop
from src.header_forensics.auth_trust import parse_auth_context, check_auth_results
from src.header_forensics.anomalies import detect_anomalies
from src.header_forensics.scoring import compute_risk_score
from src.header_forensics.report import ForensicReport
from src.origin_analysis import get_origin_analyzer
from src.url_analysis import get_url_analyzer
from src.fusion import fuse_threat_intelligence
from ..schemas import CheckUrlRequest

logger = logging.getLogger("api_analyze")
router = APIRouter()


@router.get("/health", tags=["System"])
async def health_check():
    """Liveness and operational status."""
    url_analyzer = get_url_analyzer()
    return {
        "status": "healthy",
        "grok_ai_enabled": url_analyzer.grok_client.is_available,
        "grok_model": url_analyzer.grok_client.model,
        "circuit_breaker_state": url_analyzer.grok_client.state,
    }


@router.post(
    "/check-url",
    status_code=status.HTTP_200_OK,
    tags=["URL Analysis"],
    summary="Analyze an isolated URL using Grok AI and deterministic heuristics"
)
async def check_url_endpoint(payload: CheckUrlRequest):
    """
    Evaluates a single URL against heuristic threat indicators, SQLite cache,
    and Grok AI threat intelligence.
    """
    url = (payload.url or "").strip()
    if not url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The 'url' field cannot be empty."
        )

    try:
        analyzer = get_url_analyzer()
        return analyzer.analyze_url(url)
    except Exception as e:
        logger.exception(f"Error checking URL '{url}': {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while analyzing the URL: {str(e)}"
        )


@router.post(
    "/analyze",
    status_code=status.HTTP_200_OK,
    tags=["Email Forensics"],
    summary="Ingest raw email (.eml file, form, or JSON) for multi-vector threat investigation"
)
async def analyze_email_endpoint(
    request: Request,
    file: Optional[UploadFile] = File(default=None, description="Raw .eml file upload"),
    email_file: Optional[UploadFile] = File(default=None, description="Alternative field for .eml file"),
    raw_email_text: Optional[str] = Form(default=None, description="Raw RFC 822 email text string"),
    raw_email: Optional[str] = Form(default=None, description="Alternative field for raw email text")
):
    """
    Execute full multi-vector email threat investigation:
    1. RFC 5322 header parsing & relay path reconstruction.
    2. SPF, DKIM, and DMARC authentication alignment.
    3. Dual-stack origin IP infrastructure analysis (datacenter/VPN).
    4. Deterministic + Grok AI URL payload analysis.
    5. Multi-vector threat fusion and score calibration.
    """
    eml_bytes: Optional[bytes] = None
    uploaded = file or email_file
    text_input = raw_email_text or raw_email

    # Check for application/json payload if no multipart data provided
    if uploaded is None and (text_input is None or not text_input.strip()):
        content_type = request.headers.get("content-type", "")
        if "application/json" in content_type:
            try:
                data = await request.json()
                if isinstance(data, dict):
                    text_input = (
                        data.get("raw_email_text")
                        or data.get("raw_email")
                        or data.get("raw_eml")
                    )
                    if not text_input:
                        sender = data.get("senderEmail") or data.get("from") or ""
                        subj = data.get("subject") or ""
                        headers = data.get("rawHeaders") or data.get("headers") or ""
                        body = data.get("emailBody") or data.get("body") or ""
                        parts = []
                        if headers:
                            parts.append(headers.strip())
                        if sender and "From:" not in headers:
                            parts.append(f"From: {sender}")
                        if subj and "Subject:" not in headers:
                            parts.append(f"Subject: {subj}")
                        parts.append("")
                        parts.append(body)
                        text_input = "\r\n".join(parts)
            except Exception as e:
                logger.debug(f"JSON body parse error: {e}")

    if uploaded is not None:
        try:
            eml_bytes = await uploaded.read()
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Could not read uploaded email file: {str(e)}"
            )
    elif text_input is not None and text_input.strip():
        eml_bytes = text_input.encode("utf-8", errors="replace")

    if not eml_bytes or not eml_bytes.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No email content provided. Please upload an .eml file or supply 'raw_email_text'."
        )

    try:
        # 1. Parse MIME message
        msg: Message = email.message_from_bytes(eml_bytes)

        # 2. Extract relay hops and origin IP candidate
        received_hdrs = msg.get_all("Received") or []
        relay_chain = [parse_received_header(h) for h in received_hdrs]
        all_candidates = []
        for h in received_hdrs:
            all_candidates.extend(extract_ip_candidates(h))

        origin_ip = all_candidates[-1] if all_candidates else None

        # 3. Auth & Header Anomalies
        auth_context = parse_auth_context(msg, relay_chain)
        auth_results = check_auth_results(auth_context)
        anomalies, domain_rel, brand_cat = detect_anomalies(msg, relay_chain, auth_results)
        header_risk_score = compute_risk_score(anomalies, auth_results)

        header_data = {
            "subject": msg.get("Subject", "(No Subject)"),
            "from_addr": msg.get("From", ""),
            "return_path": msg.get("Return-Path", ""),
            "message_id": msg.get("Message-ID", ""),
            "auth_results": auth_results,
            "relay_hops_count": len(relay_chain),
            "anomalies": anomalies,
            "risk_score": header_risk_score,
            "selected_origin_ip": origin_ip,
        }

        # 4. Origin IP Infrastructure Analysis
        origin_analyzer = get_origin_analyzer()
        origin_data = origin_analyzer.analyze(origin_ip) if origin_ip else {
            "ip": None, "valid": False, "risk_score": 0.0, "reasons": ["No origin IP identified"]
        }

        # 5. URL Threat Intelligence
        url_analyzer = get_url_analyzer()
        url_data = url_analyzer.analyze_email(eml_bytes)

        # 6. Multi-Vector Fusion
        fusion_report = fuse_threat_intelligence(
            header_data=header_data,
            origin_data=origin_data,
            url_data=url_data,
        )

        return {
            **fusion_report,
            "header_forensics": header_data,
            "origin_analysis": origin_data,
            "url_analysis": url_data,
        }

    except Exception as e:
        logger.exception(f"Unexpected error in email forensics pipeline: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during email investigation: {str(e)}"
        )
