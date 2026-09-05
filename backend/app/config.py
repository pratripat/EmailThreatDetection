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
PROJECT_NAME = "Email Threat Forensics & Intelligence API"
VERSION = "3.0.0"

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

# V3 Threat Intelligence Settings
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
URLHAUS_API_KEY = os.environ.get("URLHAUS_API_KEY", "").strip()

# DNS & RDAP Settings
ENABLE_DNSBL = os.environ.get("ENABLE_DNSBL", "false").lower() in ("true", "1", "yes")
ENABLE_RDAP = os.environ.get("ENABLE_RDAP", "true").lower() in ("true", "1", "yes")
ENABLE_LIVE_INTELLIGENCE = os.environ.get("ENABLE_LIVE_INTELLIGENCE", "false").lower() in ("true", "1", "yes") or bool(VIRUSTOTAL_API_KEY or ABUSEIPDB_API_KEY)

# Timeouts & Request Limits
REQUEST_TIMEOUT_SECONDS = float(os.environ.get("REQUEST_TIMEOUT_SECONDS", "3.0"))
MAX_REDIRECTS = int(os.environ.get("MAX_REDIRECTS", "5"))
MAX_REDIRECT_BYTES = int(os.environ.get("MAX_REDIRECT_BYTES", "8192"))

# Cache Settings
CACHE_TTL_SECONDS = int(os.environ.get("CACHE_TTL_SECONDS", "3600"))
MAX_CACHE_ENTRIES = int(os.environ.get("MAX_CACHE_ENTRIES", "1000"))

# ML / Content Classifier Settings
EMAIL_MODEL_PATH = os.environ.get("EMAIL_MODEL_PATH", "").strip()
USE_GPU_FOR_INFERENCE = os.environ.get("USE_GPU_FOR_INFERENCE", "false").lower() in ("true", "1", "yes")

