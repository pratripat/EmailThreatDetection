"""
Global Configuration & Settings Module
Loads environment variables, defines operational thresholds, cache policies,
timeouts, and circuit breaker settings for SIH-26106 Email Forensics.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Base Directory Resolution
CONFIG_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CONFIG_DIR.parent
DATA_DIR = PROJECT_ROOT / "data"

# Automatically load .env if available
for env_candidate in [PROJECT_ROOT / ".env", PROJECT_ROOT / "backend" / ".env"]:
    if env_candidate.exists():
        load_dotenv(env_candidate, override=False)

# API Keys
GROK_API_KEY = os.getenv("OPENAI_API_KEY") or os.getenv("GROK_API_KEY") or os.getenv("XAI_API_KEY") or ""
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY", "").strip()

# Grok / xAI Configuration
GROK_BASE_URL = os.getenv("GROK_BASE_URL", "https://api.x.ai/v1")
GROK_MODEL = os.getenv("GROK_MODEL", "grok-4.6")
GROK_TIMEOUT_SECONDS = float(os.getenv("GROK_TIMEOUT_SECONDS", "12.0"))
GROK_MAX_RETRIES = int(os.getenv("GROK_MAX_RETRIES", "2"))
GROK_CIRCUIT_BREAKER_FAILURES = int(os.getenv("GROK_CIRCUIT_BREAKER_FAILURES", "3"))
GROK_CIRCUIT_BREAKER_RESET_SECONDS = float(os.getenv("GROK_CIRCUIT_BREAKER_RESET_SECONDS", "60.0"))

# Cache Settings
CACHE_DB_PATH = DATA_DIR / "cache" / "url_checks.sqlite"
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "86400"))  # 24 hours default

# Data Paths
IP_RANGES_DIR = DATA_DIR / "ip_ranges"
BRAND_LIST_PATH = DATA_DIR / "brand_list.json"
SAMPLES_DIR = DATA_DIR / "samples"

# Scoring Thresholds
THREAT_TIER_CRITICAL = 90
THREAT_TIER_HIGH = 70
THREAT_TIER_SUSPICIOUS = 40
THREAT_TIER_LOW = 15

# General Timeouts & Requests
REQUEST_TIMEOUT_SECONDS = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "3.0"))
MAX_REDIRECTS = int(os.getenv("MAX_REDIRECTS", "5"))
MAX_REDIRECT_BYTES = int(os.getenv("MAX_REDIRECT_BYTES", "8192"))
