# SIH-26106 Email Threat Forensics & Grok AI URL Intelligence Platform

A production-grade, explainable cybersecurity email forensics and threat intelligence platform. Combines RFC 5322 header inspection, dual-stack origin infrastructure attribution, deterministic heuristic safeguards, and **xAI Grok (grok-4.6)** intelligence for robust phishing, credential harvesting, and malware detection.

---

## 🏛️ Repository Architecture

```
sih26106-email-forensics/
├── README.md                         # Complete project documentation & quickstart
├── requirements.txt                  # Consolidated Python dependencies
├── .env.example                      # Template environment variables (safe for git)
├── config/
│   ├── __init__.py
│   └── settings.py                   # API keys, timeouts, cache TTL, thresholds, feature flags
│
├── data/
│   ├── ip_ranges/                    # Dual-stack CIDR range feeds
│   │   ├── datacenter_ipv4.txt / ipv6.txt
│   │   └── vpn_ipv4.txt / ipv6.txt
│   ├── brand_list.json               # Protected brand list for impersonation/typosquatting
│   ├── samples/                      # Forensic demonstration email artifacts
│   │   ├── sample_clean.eml
│   │   └── sample_spoofed.eml
│   └── cache/
│       └── url_checks.sqlite         # Persistent TTL-aware SHA-256 URL threat cache
│
├── src/
│   ├── header_forensics/             # RFC 5322 header & authentication analysis
│   │   ├── parser.py                 # Relay hop extraction & IP candidate isolation
│   │   ├── domain_utils.py           # PSL resolution, homoglyphs, and brand loading
│   │   ├── auth_trust.py             # SPF / DKIM / DMARC verification & MTA alignment
│   │   ├── anomalies.py              # Header anomaly & display-name spoofing engine
│   │   ├── scoring.py                # Weighted forensic scoring with evidence gating
│   │   └── report.py                 # Explainable forensic report dataclasses
│   │
│   ├── origin_analysis/              # Dual-stack sender IP infrastructure attribution
│   │   ├── ip_classifier.py          # Global, private, loopback, bogon classification
│   │   ├── range_lookup.py           # O(log N) bisect binary search over CIDR blocks
│   │   └── analyzer.py               # Origin infrastructure risk evaluator
│   │
│   ├── url_analysis/                 # Grok-powered URL threat analysis engine
│   │   ├── extractor.py              # Multi-part URL extraction (text, HTML, headers)
│   │   ├── features.py               # Deterministic lexical, brand, and TLD indicators
│   │   ├── grok_client.py            # xAI client with circuit breaker & retry fallback
│   │   ├── prompts.py                # Structured prompts & multi-format response parsers
│   │   ├── cache.py                  # SQLite cache manager (SHA-256 keys, TTL purge)
│   │   └── analyzer.py               # Orchestrator blending Grok AI with heuristics
│   │
│   └── fusion/                       # Multi-vector intelligence synthesis
│       └── hybrid_score.py           # Calibrated threat scoring & operational tiering
│
├── backend/
│   ├── api/
│   │   ├── main.py                   # Primary FastAPI application entrypoint
│   │   ├── routes/
│   │   │   └── analyze.py            # POST /analyze & POST /check-url
│   │   └── schemas.py                # Pydantic request & response models
│   ├── dashboard/
│   │   └── app.py                    # Interactive Streamlit security analyst workstation
│   ├── app/                          # Classic FastAPI service (backward compatible)
│   └── tests/                        # Full test suite (unit, contract, API, regression)
│
├── tests/                            # Modular unit test suite (offline / mocked)
│   ├── test_url_analysis/            # Deterministic features & Grok client tests
│   ├── test_header_forensics/        # Header parsing & anomaly tests
│   ├── test_origin_analysis/         # IP classification & CIDR bisect tests
│   └── test_fusion/                  # Threat fusion & escalation tests
│
└── scripts/
    ├── download_ip_ranges.sh         # IP range updater script
    └── precache_demo_urls.py         # SQLite cache pre-warming script
```

---

## ⚡ Quickstart Guide

### 1. Environment Setup

```bash
# Clone the repository and navigate to root
git clone <repo-url>
cd EmailThreatDetection

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install all dependencies
pip install -r requirements.txt
```

### 2. Configure Environment Variables

Copy the sanitized template to `.env`:

```bash
cp .env.example .env
```

Edit `.env` to add your Grok (xAI) API key:

```ini
OPENAI_API_KEY=xai-your-actual-api-key-here
GROK_BASE_URL=https://api.x.ai/v1
GROK_MODEL=grok-4.6
```

> **Note:** If `OPENAI_API_KEY` is omitted or set to a placeholder, the system automatically runs in **offline deterministic mode** without failing.

### 3. Pre-Cache Demo URLs (Optional)

Pre-populate the SQLite cache for instant response times on common demo URLs:

```bash
python scripts/precache_demo_urls.py
```

### 4. Run the FastAPI Service

```bash
python -m backend.api.main
# Or:
uvicorn backend.api.main:app --host 0.0.0.0 --port 8000 --reload
```

- Interactive Swagger Docs: `http://localhost:8000/docs`
- ReDoc API Reference: `http://localhost:8000/redoc`

### 5. Launch the Security Analyst Dashboard

```bash
streamlit run backend/dashboard/app.py
```

Opens at `http://localhost:8501`. Features:
- 1-click loading of sample clean and spoofed emails.
- Live threat score gauge, operational tiering, and primary attack vector attribution.
- Interactive Grok AI URL Scanner with technical reasoning and heuristic breakdown.
- Cache management and circuit breaker status.

---

## 📡 API Endpoints

### 1. `POST /api/check-url` (or `POST /check-url`)
Inspect an isolated URL using Grok AI and deterministic heuristics.

**Request:**
```json
{
  "url": "https://paypa1-security-verify.com/login"
}
```

**Response (HTTP 200):**
```json
{
  "url": "https://paypa1-security-verify.com/login",
  "domain": "paypa1-security-verify.com",
  "reputation": "MALICIOUS",
  "threatScore": 95,
  "flags": [
    "Possible brand impersonation: Leetspeak/typo impersonation of brand 'paypal' in token 'paypa1'",
    "Contains security-sensitive keywords: ['login']",
    "Grok: Typosquatted brand credential harvesting"
  ],
  "grok_analysis": {
    "verdict": "PHISHING",
    "confidence": 0.96,
    "reason": "Deceptive homoglyph domain mimicking PayPal to harvest login credentials."
  },
  "cached": true
}
```

### 2. `POST /api/analyze` (or `POST /analyze`)
Ingest raw email `.eml` artifact, multipart form, or JSON for multi-vector threat investigation.

**Response includes:**
- `final_threat_score`: 0-100 calibrated risk score.
- `threat_tier`: `CRITICAL`, `HIGH`, `SUSPICIOUS`, or `LOW`.
- `primary_threat_vector`: Primary detected cyberattack tactic.
- `header_forensics`: SPF, DKIM, DMARC alignment, Received relay hops, detected anomalies.
- `origin_analysis`: IP classification, datacenter CIDR match, VPN/Tor exit node match.
- `url_analysis`: Complete breakdown of all extracted URLs with Grok AI classifications.
- `recommendation`: Concrete SOC / end-user advisory.

### 3. `GET /api/health`
System liveness probe and Grok AI circuit breaker state.

---

## 🧪 Running Automated Tests

Run the modular unit test suite (zero network dependencies, fully mocked):

```bash
python -m pytest tests/ -v
```

Run the complete backend integration and regression test suite (111 tests total):

```bash
python -m pytest backend/tests/ -v
```

All 111 tests pass with zero network dependencies.

---

## 🔒 Security Best Practices
- **No Hardcoded Keys:** Secrets are read from environment variables or `.env`. `.env` and `*.sqlite` are strictly git-ignored.
- **Circuit Breaker:** Automatically trips after 3 consecutive failures to avoid latency spikes and unneeded upstream requests.
- **Deterministic Heuristics:** Brand typosquatting, raw IP detection, and abuse-prone TLD heuristics guarantee protection even if the LLM endpoint is degraded or offline.
