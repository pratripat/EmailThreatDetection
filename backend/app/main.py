"""
FastAPI Backend Application Entrypoint
Exposes email threat forensics API to the frontend with CORS, OpenAPI docs,
and structured investigation routes.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from .config import PROJECT_NAME, VERSION, API_V1_STR, CORS_ORIGINS
from .api.routes import router as api_router

app = FastAPI(
    title=PROJECT_NAME,
    version=VERSION,
    description="Backend API serving structured InvestigationData telemetry for email threat forensics.",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Configure CORS for local frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API routes under /api
app.include_router(api_router, prefix=API_V1_STR)


@app.get("/", tags=["System"])
async def root():
    return {
        "service": PROJECT_NAME,
        "version": VERSION,
        "health": f"{API_V1_STR}/health",
        "analyze": f"{API_V1_STR}/analyze-email",
        "docs": "/docs"
    }


if __name__ == "__main__":
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)
