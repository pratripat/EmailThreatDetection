from pathlib import Path
import os

# Base Directories
APP_DIR = Path(__file__).resolve().parent
BACKEND_DIR = APP_DIR.parent
ROOT_DIR = BACKEND_DIR.parent

# Data Directory Resolution
DEFAULT_DATA_DIR = BACKEND_DIR / "data"
if not DEFAULT_DATA_DIR.exists():
    DEFAULT_DATA_DIR = ROOT_DIR / "data"

DATA_DIR = Path(os.environ.get("SIH_DATA_DIR", str(DEFAULT_DATA_DIR)))

# API Configuration
API_V1_STR = "/api"
PROJECT_NAME = "Email Threat Forensics API"
VERSION = "2.6.0"

# CORS configuration for frontend development
CORS_ORIGINS = [
    "http://localhost",
    "http://localhost:3000",
    "http://localhost:5173",
    "http://localhost:8080",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:8080",
    "*",
]
