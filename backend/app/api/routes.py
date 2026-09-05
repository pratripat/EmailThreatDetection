"""
FastAPI API Endpoints
Routes:
- GET /api/health: Health & liveness status
- POST /api/analyze-email: Complete email threat analysis pipeline accepting
  either multipart/form-data upload (.eml) or raw email text
"""

import logging
from typing import Optional
from fastapi import APIRouter, File, UploadFile, Form, HTTPException, status, Request
from fastapi.responses import JSONResponse

from ..models.investigation import InvestigationData
from ..services.investigation_service import InvestigationService
from ..config import VERSION, PROJECT_NAME

logger = logging.getLogger(__name__)

router = APIRouter()
investigation_service = InvestigationService()


@router.get("/health", tags=["System"])
async def health_check():
    """Liveness probe verifying that the backend API is operational."""
    return {
        "status": "healthy",
        "service": PROJECT_NAME,
        "version": VERSION
    }


@router.post(
    "/analyze-email",
    response_model=InvestigationData,
    response_model_by_alias=True,
    status_code=status.HTTP_200_OK,
    tags=["Analysis"],
    summary="Analyze an incoming email artifact and return structured investigation telemetry"
)
async def analyze_email_endpoint(
    request: Request,
    file: Optional[UploadFile] = File(default=None, description="Raw .eml email file upload"),
    email: Optional[UploadFile] = File(default=None, description="Alternative field name for .eml file upload"),
    raw_email: Optional[str] = Form(default=None, description="Raw email text content"),
    raw_email_text: Optional[str] = Form(default=None, description="Alternative field name for raw email text")
):
    """
    Ingest a raw email artifact (.eml file or raw MIME string) and execute
    the deterministic investigation pipeline:
    - Header & MIME parsing
    - Relay path reconstruction & dual-stack origin analysis
    - SPF/DKIM/DMARC alignment validation
    - PSL-aware URL heuristic & typosquatting detection
    - Baseline content intent & social engineering analysis
    - IOC extraction & attack graph synthesis
    """
    eml_bytes: Optional[bytes] = None
    filename: Optional[str] = None

    uploaded_file = file or email
    raw_text = raw_email or raw_email_text

    # Support application/json payloads (e.g. from frontend form or API callers)
    if uploaded_file is None and (raw_text is None or not raw_text.strip()):
        content_type = request.headers.get("content-type", "")
        if "application/json" in content_type:
            try:
                json_data = await request.json()
                if isinstance(json_data, dict):
                    raw_text = (
                        json_data.get("raw_email_text")
                        or json_data.get("raw_email")
                        or json_data.get("raw_eml")
                    )
                    if not raw_text or not raw_text.strip():
                        sender = json_data.get("senderEmail") or json_data.get("sender_email") or ""
                        subj = json_data.get("subject") or ""
                        headers = json_data.get("rawHeaders") or json_data.get("raw_headers") or ""
                        body = json_data.get("emailBody") or json_data.get("email_body") or ""

                        parts = []
                        if headers:
                            parts.append(headers.strip())
                        if sender and "From:" not in headers:
                            parts.append(f"From: {sender}")
                        if subj and "Subject:" not in headers:
                            parts.append(f"Subject: {subj}")
                        parts.append("")
                        parts.append(body)
                        raw_text = "\r\n".join(parts)
            except Exception as e:
                logger.debug(f"Could not parse request body as JSON: {e}")
    if uploaded_file is not None:
        filename = uploaded_file.filename
        try:
            eml_bytes = await uploaded_file.read()
        except Exception as e:
            logger.error(f"Error reading uploaded file: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Could not read uploaded email file: {str(e)}"
            )

    elif raw_text is not None and raw_text.strip():
        eml_bytes = raw_text.encode('utf-8', errors='replace')
        filename = "raw_input.eml"

    if not eml_bytes or not eml_bytes.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No email content provided. Please upload an .eml file via 'email' field or provide 'raw_email_text'."
        )

    try:
        report = investigation_service.analyze_email(eml_bytes, filename=filename)
        return report
    except Exception as e:
        logger.exception("Unexpected error during email investigation pipeline")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected internal error occurred while analyzing the email. Details logged server-side."
        )
