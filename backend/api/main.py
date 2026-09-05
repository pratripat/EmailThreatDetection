"""
Main FastAPI Application Entry Point
Exposes REST API endpoints for email forensic analysis and Grok URL intelligence.
"""

import sys
import logging
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import settings
from backend.api.routes.analyze import router as analyze_router
from src.url_analysis import get_url_analyzer
from src.origin_analysis import get_origin_analyzer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("api_main")

app = FastAPI(
    title="SIH-26106 Email Threat Forensics & Grok URL Analyzer API",
    version="3.0.0",
    description="Multi-vector cyber threat intelligence combining header forensics, origin IP attribution, and Grok AI URL detection.",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permits all origins for testing and local dashboard integration
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount routes under both /api and root / for maximum client compatibility
app.include_router(analyze_router, prefix="/api")
app.include_router(analyze_router)


@app.on_event("startup")
async def startup_event():
    """Warm up cached analyzers and verify Grok client status."""
    logger.info("Initializing threat intelligence engines...")
    url_analyzer = get_url_analyzer()
    get_origin_analyzer()
    if url_analyzer.grok_client.is_available:
        logger.info(f"Grok AI URL analysis is ACTIVE (Model: {url_analyzer.grok_client.model})")
    else:
        logger.info("Grok AI URL analysis running in offline deterministic mode.")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.api.main:app", host="0.0.0.0", port=8000, reload=True)
