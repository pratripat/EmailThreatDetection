# Frontend Application Workspace

This directory is reserved for the frontend team's client-side user interface (React / Next.js / Vue / Vite).

## Backend API Integration Contract

The backend provides an email threat investigation API running on `http://localhost:8000`.

### Endpoints

- **Health Check**: `GET /api/health`
- **Email Investigation**: `POST /api/analyze-email`
  - Input: `multipart/form-data` with form field `email` (the raw `.eml` file).
  - Output: `application/json` returning the canonical `InvestigationData` schema.

### Canonical Response Schema (`InvestigationData`)

The backend guarantees the following JSON structure:

```json
{
  "id": "uuid-string",
  "subject": "Email Subject",
  "from": "Display Name <sender@domain.com>",
  "to": "recipient@target.com",
  "receivedDate": "2026-09-04T12:00:00Z",
  "threatScore": 85,
  "threatLevel": "HIGH",
  "threatType": "PHISHING",
  "confidence": 0.0,
  "authStatus": "FAILED",
  "breakdown": {
    "headerAnomalies": 85,
    "authentication": 45,
    "urlRisk": 100,
    "contentNlp": 80,
    "senderReputation": 0
  },
  "suspiciousReasons": [
    "SPF check: FAIL",
    "DKIM check: none",
    "Display name impersonates 'paypal'"
  ],
  "headerHops": [
    {
      "hopNumber": 1,
      "ip": "45.135.232.19",
      "hostname": "relay.server.com",
      "country": "UNKNOWN",
      "city": null,
      "asn": "UNKNOWN",
      "isp": "UNKNOWN",
      "reputation": "SUSPICIOUS",
      "firstSeen": "UNKNOWN",
      "threatFeeds": {
        "abuseIpDb": "NOT_CHECKED",
        "virusTotal": "NOT_QUERIED",
        "spamhausListed": false
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
    "notes": []
  },
  "urls": [
    {
      "url": "http://paypal-verify-account.freehostingnow.net/login",
      "domain": "freehostingnow.net",
      "registeredAgeDays": -1,
      "reputation": "MALICIOUS",
      "threatScore": 100,
      "flags": ["Uses unencrypted HTTP", "Phishing keywords"],
      "redirectChain": []
    }
  ],
  "contentAi": {
    "classification": "PHISHING",
    "confidence": 0.5,
    "intents": ["Credential Harvesting", "Urgent Coercion"],
    "suspiciousPhrases": [
      {
        "phrase": "urgent",
        "signalType": "Urgency signal"
      }
    ],
    "featureContributions": []
  },
  "iocs": {
    "ipAddresses": ["45.135.232.19"],
    "domains": ["freehostingnow.net"],
    "urls": ["http://paypal-verify-account.freehostingnow.net/login"],
    "emailAddresses": ["security@freehostingnow.net"],
    "hashes": []
  },
  "attackGraph": {
    "nodes": [
      { "id": "node_email", "label": "Email Subject", "sublabel": "Target Artifact", "type": "email", "status": "critical" },
      { "id": "domain_freehostingnow.net", "label": "freehostingnow.net", "sublabel": "Sender Domain", "type": "domain", "status": "critical" }
    ],
    "edges": [
      { "from": "node_email", "to": "domain_freehostingnow.net", "label": "From Domain" }
    ]
  },
  "rawHeaders": "...",
  "rawBody": "..."
}
```

See `backend/tests/fixtures/sample_investigation_response.json` for a real-world example response.
