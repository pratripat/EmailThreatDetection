# Email Threat Detection & Forensics — Backend Application

A deterministic, explainable email threat investigation engine and FastAPI backend service built for pairing with the frontend investigation dashboard.

## 1. Overview & Architecture

The backend orchestrates multiple specialized, offline-capable analyzers to generate a comprehensive `InvestigationData` payload for any ingested `.eml` artifact:

```
                      Raw .eml Upload
                             │
                             ▼
                ┌──────────────────────────┐
                │      FastAPI Router      │
                │  POST /api/analyze-email │
                └────────────┬─────────────┘
                             │
                             ▼
                ┌──────────────────────────┐
                │  Investigation Service   │
                └────────────┬─────────────┘
                             │
       ┌─────────────────────┼─────────────────────┐
       ▼                     ▼                     ▼
┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│     MIME     │      │    Header    │      │    Origin    │
│   Analysis   │      │  Forensics   │      │   Analysis   │
└──────┬───────┘      └──────┬───────┘      └──────┬───────┘
       │                     │                     │
       └─────────────────────┼─────────────────────┘
                             ▼
       ┌─────────────────────┼─────────────────────┐
       ▼                     ▼                     ▼
┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│     URL      │      │  Content AI  │      │     IOC      │
│   Analysis   │      │  (Baseline)  │      │  Extraction  │
└──────┬───────┘      └──────┬───────┘      └──────┬───────┘
       │                     │                     │
       └─────────────────────┼─────────────────────┘
                             │
                             ▼
                ┌──────────────────────────┐
                │  Attack Graph Synthesis  │
                └────────────┬─────────────┘
                             │
                             ▼
                ┌──────────────────────────┐
                │    Multi-Vector Score    │
                │       Aggregation        │
                └────────────┬─────────────┘
                             │
                             ▼
                   InvestigationData JSON
```

### Module Structure

- `app/api/routes.py`: REST routes (`GET /api/health`, `POST /api/analyze-email`).
- `app/models/investigation.py`: Strongly-typed Pydantic contract models for `InvestigationData`.
- `app/services/investigation_service.py`: Central orchestration coordinating analyzers into canonical responses.
- `app/analyzers/header_forensics.py`: Received-header relay reconstruction, RFC 5322 parsing, PSL domain relationship matching, brand impersonation with Cyrillic homoglyph support, and evidence-gated scoring.
- `app/analyzers/origin_analysis.py`: Dual-stack IPv4/IPv6 indexed CIDR lookup against VPN and datacenter ranges with O(log N) bisect search.
- `app/analyzers/url_analysis.py`: Extracts URLs from plain text and HTML, performs 11-step heuristic risk scoring (Punycode, typosquats, credential masking, HTTP, suspicious TLDs).
- `app/analyzers/content_analysis.py`: Deterministic baseline heuristic intent matcher identifying urgent coercion, credential solicitation, and financial manipulation.
- `app/analyzers/ioc_extraction.py`: Deduplicated network and host indicator extraction (IPs, domains, URLs, email addresses, attachment SHA-256 hashes).
- `app/analyzers/attack_graph.py`: Builds directed provenance and attack graphs connecting email artifacts, sender domains, relays, and embedded resources.

---

## 2. Setup & Installation

### Requirements
- Python 3.10+
- Linux / macOS / Windows

### Dependencies Installation

```bash
cd backend
pip install -r requirements.txt
```

---

## 3. Starting the Backend Server

Start the server using `uvicorn`:

```bash
# From the backend/ directory:
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Or run directly from repo root:

```bash
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

The API will be available at:
- **API Root**: `http://localhost:8000/`
- **Interactive Swagger Docs**: `http://localhost:8000/docs`
- **ReDoc Documentation**: `http://localhost:8000/redoc`

---

## 4. API Endpoints

### Liveness Probe
- **Method**: `GET`
- **Path**: `/api/health`
- **Response**:
```json
{
  "status": "healthy",
  "service": "Email Threat Forensics API",
  "version": "2.6.0"
}
```

### Analyze Email Artifact
- **Method**: `POST`
- **Path**: `/api/analyze-email`
- **Content-Type**: `multipart/form-data`
- **Form Parameters**:
  - `email` (file): Uploaded `.eml` raw email file (recommended).
  - `raw_email_text` (string, optional): Raw MIME string if not sending via file upload.

#### Example `curl` Request

```bash
curl -X POST "http://localhost:8000/api/analyze-email" \
     -H "Accept: application/json" \
     -F "email=@tests/fixtures/sample_spoofed.eml"
```

#### Example JSON Response

```json
{
  "id": "7b79d20c-550a-48d0-9941-944f2d3d3cfa",
  "subject": "Urgent: Your Account Has Been Limited - Verify Now",
  "from": "PayPal Security Team <security@freehostingnow.net>",
  "to": ["victim@example.com"],
  "receivedDate": "2026-09-04T23:31:23.484201+00:00",
  "threatScore": 85,
  "threatLevel": "HIGH",
  "threatType": "PHISHING",
  "confidence": 0.9,
  "authStatus": "FAILED",
  "breakdown": {
    "headerAnomalies": 85,
    "authentication": 45,
    "urlRisk": 100,
    "contentNlp": 80,
    "senderReputation": 0
  },
  "suspiciousReasons": [
    "SPF check: FAIL (hard failure — domain owner explicitly disavows this sender)",
    "DKIM check: none (expected 'pass')",
    "DMARC check: fail (expected 'pass')",
    "Display name impersonates 'paypal' but sending domain is 'freehostingnow.net' with failing authentication — critical display-name spoofing indicator",
    "Embedded URL 'http://paypal-verify-account.freehostingnow.net/login' flagged as MALICIOUS: Uses unencrypted HTTP instead of HTTPS (+20), Multiple hyphens in domain (+15), Contains security-sensitive keywords: ['login', 'verify', 'account'] (+25), Possible brand impersonation: Brand 'paypal' found in subdomain of unrelated domain ('paypal-verify-account.freehostingnow.net') (+40)",
    "Email body exhibits social engineering indicators: Credential Harvesting, Urgent Coercion"
  ],
  "headerHops": [
    {
      "hopNumber": 1,
      "ip": "0.0.0.0",
      "hostname": "mail.suspicious-relay.ru",
      "country": null,
      "city": null,
      "asn": null,
      "isp": null,
      "reputation": "UNKNOWN",
      "firstSeen": null,
      "threatFeeds": {
        "abuseIpDb": "NOT_CHECKED",
        "virusTotal": "NOT_QUERIED",
        "spamhaus": "NOT_CHECKED"
      }
    },
    {
      "hopNumber": 2,
      "ip": "185.220.101.47",
      "hostname": "unknown [185.220.101.47]",
      "country": null,
      "city": null,
      "asn": null,
      "isp": null,
      "reputation": "VPN",
      "firstSeen": null,
      "threatFeeds": {
        "abuseIpDb": "NOT_CHECKED",
        "virusTotal": "NOT_QUERIED",
        "spamhaus": "NOT_CHECKED"
      }
    },
    {
      "hopNumber": 3,
      "ip": "45.135.232.19",
      "hostname": "mx1.freehostingnow.net (mx1.freehostingnow.net [45.135.232.19])",
      "country": null,
      "city": null,
      "asn": null,
      "isp": null,
      "reputation": "UNKNOWN",
      "firstSeen": null,
      "threatFeeds": {
        "abuseIpDb": "NOT_CHECKED",
        "virusTotal": "NOT_QUERIED",
        "spamhaus": "NOT_CHECKED"
      }
    }
  ],
  "authentication": {
    "spf": "FAILED",
    "dkim": "NONE",
    "dmarc": "FAILED",
    "fromDomain": "freehostingnow.net",
    "returnPathDomain": "freehostingnow.net",
    "alignmentMatched": true,
    "notes": [
      "Authserv ID (mx.google.com) does not match top receiving MTA (mail.suspicious-relay.ru)"
    ]
  },
  "urls": [
    {
      "url": "http://paypal-verify-account.freehostingnow.net/login",
      "domain": "freehostingnow.net",
      "registeredAgeDays": null,
      "reputation": "MALICIOUS",
      "threatScore": 100,
      "flags": [
        "Uses unencrypted HTTP instead of HTTPS (+20)",
        "Multiple hyphens in domain (+15)",
        "Contains security-sensitive keywords: ['login', 'verify', 'account'] (+25)",
        "Possible brand impersonation: Brand 'paypal' found in subdomain of unrelated domain ('paypal-verify-account.freehostingnow.net') (+40)"
      ],
      "redirectChain": []
    }
  ],
  "contentAi": {
    "classification": "PHISHING",
    "confidence": 0.5,
    "intents": ["Credential Harvesting", "Urgent Coercion"],
    "suspiciousPhrases": [
      "unusual activity",
      "urgent",
      "limited",
      "immediately",
      "suspended",
      "within 24 hours",
      "account has been limited"
    ],
    "featureContributions": {}
  },
  "iocs": {
    "ips": ["185.220.101.47", "45.135.232.19"],
    "domains": ["example.com", "freehostingnow.net"],
    "urls": ["http://paypal-verify-account.freehostingnow.net/login"],
    "emails": ["bounce@freehostingnow.net", "security@freehostingnow.net", "victim@example.com"],
    "hashes": []
  },
  "attackGraph": {
    "nodes": [
      { "id": "node_email", "label": "Urgent: Your Account Has Been Limited - Verify Now", "type": "email" },
      { "id": "domain_freehostingnow.net", "label": "freehostingnow.net", "type": "domain" },
      { "id": "ip_45.135.232.19", "label": "45.135.232.19", "type": "ip" },
      { "id": "url_0", "label": "http://paypal-verify-account.freehostingnow.net/login", "type": "page" },
      { "id": "action_harvest", "label": "Harvest Credentials", "type": "action" }
    ],
    "edges": [
      { "source": "node_email", "target": "domain_freehostingnow.net", "relation": "Sent From" },
      { "source": "domain_freehostingnow.net", "target": "ip_45.135.232.19", "relation": "Relayed Via" },
      { "source": "node_email", "target": "url_0", "relation": "Embedded Link" },
      { "source": "url_0", "target": "domain_freehostingnow.net", "relation": "Sent From" },
      { "source": "url_0", "target": "action_harvest", "relation": "Submits To" }
    ]
  }
}
```

---

## 5. Current Capabilities vs. Deferred V3 Capabilities

| Area | Currently Implemented (V2.6 Backend) | Deferred to V3 (External Threat Intel) |
| :--- | :--- | :--- |
| **MIME / Headers** | Robust standard library RFC 5322/MIME parsing, attachments, embedded URLs | Multi-part archive unpacking |
| **Relay Chain** | Bottom-up routing-based origin candidate selection, RFC 5737 doc handling | BGP AS-path verification |
| **Origin IP** | Offline indexed CIDR check for VPN / Datacenter / Non-routable IPs | Live Tor exit list, MaxMind GeoIP, live AbuseIPDB query |
| **Authentication** | Claimed SPF/DKIM/DMARC parsing, DKIM alignment vs From, boundary correlation | Live DNS TXT query, live DKIM RSA/Ed25519 signature crypto verify |
| **URLs** | 11-step heuristic detection, PSL registered domain extraction, typosquats | Live WHOIS domain age, URL redirect unshortening, Google SafeBrowsing |
| **Content** | Deterministic intent pattern matching (Urgent, Credential, Financial) | Fine-tuned DeBERTa/RoBERTa transformer, SHAP feature attribution |
| **Attack Graph** | Directed graph derived strictly from parsed headers, URLs, and intents | External infrastructure pivoting (C2 attribution, passive DNS) |

---

## 6. Running Tests

Run the complete test suite with `pytest`:

```bash
pytest -v backend/tests
```

Or run individual test modules:

```bash
python -m unittest backend/tests/test_api.py
python -m unittest backend/tests/test_contract.py
python -m unittest backend/tests/test_forensics_v25.py
python -m unittest backend/tests/test_forensics_v26.py
python backend/tests/test_urls.py
```
