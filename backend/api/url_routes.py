from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from typing import Dict, Any

try:
    from ..app.analyzers.grok_url_analyzer import GrokURLAnalyzer
except Exception:
    from app.analyzers.grok_url_analyzer import GrokURLAnalyzer

router = APIRouter(tags=["URL Analysis"])
analyzer = GrokURLAnalyzer()


class CheckUrlRequest(BaseModel):
    url: str


@router.post("/check-url")
async def check_url(payload: CheckUrlRequest) -> Dict[str, Any]:
    """Analyze a single URL using Grok AI combined with deterministic heuristics."""
    raw_url = payload.url.strip() if payload.url else ""
    if not raw_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The 'url' field cannot be empty."
        )
    return analyzer.analyze_url(raw_url)


@router.get("/url-health")
async def url_health_check():
    return {"status": "URL analyzer is ready", "grok_enabled": analyzer.enabled}