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

## 5. V3 Threat Intelligence & AI Investigation Layer

The system features a multi-stream threat intelligence and AI layer that preserves forensic truthfulness and explicit provenance (`VERIFIED`, `OBSERVED`, `HEURISTIC`, `MODEL_PREDICTION`, `NOT_CHECKED`, `UNAVAILABLE`, `ERROR`).

| Intelligence Vector | Implementation & Guardrails | Provenance |
| :--- | :--- | :--- |
| **IP Intelligence** | AbuseIPDB v2 + VirusTotal v3 with thread-safe TTL LRU caching. **Strict non-routable filter**: never queries private (RFC1918), loopback, link-local, multicast, or documentation IPs. | `VERIFIED` (external API) / `OBSERVED` (private IP) / `NOT_CHECKED` |
| **Domain Intelligence** | Internationalized Domain Name (IDN) Punycode normalization and public RDAP (RFC 7480) query for domain registration date, age, and registrar. Flags newly registered domains (<30 days). | `VERIFIED` (RDAP query) / `NOT_CHECKED` (offline) |
| **DNS Intelligence** | DNS record resolution (MX, A, TXT/SPF, DMARC, NS) and DNSBL inspection (`zen.spamhaus.org`, `bl.spamcop.net`) via `dnspython` with bounded 2s timeouts. | `VERIFIED` (DNS answers) / `NOT_CHECKED` |
| **URL Reputation** | VirusTotal URL API v3 and URLhaus with unpadded base64 identifier lookup and category aggregation. | `VERIFIED` (VT/URLhaus) / `HEURISTIC` (local heuristics) |
| **SSRF-Safe Redirects** | Pre-flight DNS resolution checking **every candidate destination IP**. Strictly blocks 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, cloud metadata `169.254.169.254`, IPv6 `::1`, and multicast before establishing any connection. Caps hops at 5 with stream size limit. | `VERIFIED` (public hops) / `OBSERVED` (SSRF attempt blocked) |
| **Content AI / ML** | Local HuggingFace / PyTorch transformer pipeline support with honest heuristic fallback. **Forensic honesty invariant**: never fabricates synthetic ML probabilities or fake SHAP/LIME values when running heuristic rules. | `MODEL_PREDICTION` (loaded model) / `HEURISTIC` (pattern matcher) |
| **Evidence Fusion Engine** | Multivariate mathematical score derivation, centralized threat level classification (`CRITICAL`, `HIGH`, `SUSPICIOUS`, `LOW`, `CLEAN`), and auditable explanation log. Preserves deterministic baseline scores while boosting on verified threat indicators. | Mathematical synthesis |

---

## 6. Running Tests

Run the complete test suite (80 tests) with `pytest`:

```bash
python3 -m pytest backend/tests -v
```

Or run individual test suites:

```bash
# Baseline contract & API tests:
python3 -m pytest backend/tests/test_api.py -v
python3 -m pytest backend/tests/test_contract.py -v

# V2.5 & V2.6 forensic hardening tests:
python3 -m pytest backend/tests/test_forensics_v25.py -v
python3 -m pytest backend/tests/test_forensics_v26.py -v
python3 -m pytest backend/tests/test_urls.py -v

# V3 Intelligence & Fusion tests:
python3 -m pytest backend/tests/test_v3_cache.py -v
python3 -m pytest backend/tests/test_v3_ip_and_domain.py -v
python3 -m pytest backend/tests/test_v3_dns.py -v
python3 -m pytest backend/tests/test_v3_urls.py -v
python3 -m pytest backend/tests/test_v3_content.py -v
python3 -m pytest backend/tests/test_v3_fusion.py -v
```

