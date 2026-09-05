"""
FastAPI Backend Application Entrypoint
Exposes email threat forensics API to the frontend with CORS, OpenAPI docs,
and structured investigation routes.
"""

import sys
import os
from pathlib import Path

# Ensure backend and root paths are in sys.path and PYTHONPATH so both
# 'py -m app.main' (from backend/) and 'py -m backend.app.main' (from project root) work seamlessly.
CURRENT_FILE = Path(__file__).resolve()
APP_DIR = CURRENT_FILE.parent
BACKEND_DIR = APP_DIR.parent
ROOT_DIR = BACKEND_DIR.parent

for candidate_path in [str(BACKEND_DIR), str(ROOT_DIR)]:
    if candidate_path not in sys.path:
        sys.path.insert(0, candidate_path)

existing_pythonpath = os.environ.get("PYTHONPATH", "")
extra_paths = [str(BACKEND_DIR), str(ROOT_DIR)]
new_pythonpath_items = [p for p in extra_paths if p not in existing_pythonpath.split(os.pathsep)]
if new_pythonpath_items:
    os.environ["PYTHONPATH"] = os.pathsep.join(
        new_pythonpath_items + ([existing_pythonpath] if existing_pythonpath else [])
    )

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
    # If running from inside the backend directory, target 'app.main:app'
    # If running from project root, target 'backend.app.main:app'
    cwd = Path.cwd().resolve()
    if cwd == BACKEND_DIR:
        target = "app.main:app"
    elif (cwd / "backend").exists():
        target = "backend.app.main:app"
    else:
        target = "app.main:app"

    uvicorn.run(target, host="0.0.0.0", port=8000, reload=True)
