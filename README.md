# Email Security Shield

A Gmail Add-on that analyzes the currently opened email, detects phishing and malicious indicators, and returns an **explainable risk score, verdict, and recommended action**.

---

## Architecture Overview

The system uses a simple **client–server architecture**:

**Gmail Add-on (Google Apps Script) ↔ FastAPI Backend**

```text
Gmail
  ↓
Gmail Add-on / Apps Script
  ↓
Extract Email Data
  ↓
HTTPS POST /api/v1/analyze
  ↓
FastAPI Backend
  ↓
Analyzers
  ├─ Identity
  ├─ Links
  ├─ Authentication
  ├─ Content
  ├─ Structure
  └─ Attachments
  ↓
Scoring Engine
  ↓
JSON Response
Score + Verdict + Signals + Recommendation
  ↓
Result UI in Gmail
```

Each analyzer is responsible for detecting a specific family of suspicious behaviors and produces **signals**.
The Scoring Engine then combines those signals into the final risk score and verdict.

This separation keeps detection logic independent from scoring, making the system easier to **test, tune, and extend**.

> **Architecture Diagram:**
> `[Add architecture image here]`

---

## Repository Structure

```text
ProjectUpwind/
│
├── README.md
│
├── backend/
│   ├── main.py                     # FastAPI app & the /api/v1/analyze endpoint
│   ├── parser.py                   # Normalizes incoming JSON, fills in defaults
│   ├── scoring.py                  # Scoring Engine
│   ├── identity_analyzer.py        # Sender / brand-impersonation checks
│   ├── link_analyzer.py            # Link destination vs. displayed text checks
│   ├── authentication_analyzer.py  # SPF / DKIM / DMARC checks
│   ├── content_analyzer.py         # Social-engineering language checks
│   ├── structure_analyzer.py       # HTML structure / hidden-content checks
│   ├── attachment_analyzer.py      # Attachment filename / type checks
│   ├── domain_utils.py             # Shared domain & URL helpers
│   └── knowledge.py                # Static reference data (brand domains, URL shorteners)
│
├── gmail-addon/
│   ├── Code.gs                     # Gmail Add-on logic (see Gmail Add-on Setup below)
│   └── appsscript.json             # Gmail Add-on configuration
│
└── docs/
    ├── architecture.png
    └── product-review.pdf
```

* Each `*_analyzer.py` file is an independent security check - it takes the parsed email and returns a list of signals.
* `scoring.py` combines signals into the final score and verdict.
* `domain_utils.py` - shared domain and URL utilities used by multiple analyzers.
* `knowledge.py` - static reference data such as brand domains and URL shorteners.

**Planned, not yet in this repository:** the contents of `docs/` (architecture diagram and product review document).

---

## Setup & Run

### Prerequisites

* Python 3.10+
* Google account with Apps Script access
* Gmail API enabled
* ngrok for local development

### Backend

All backend commands are run from the `backend/` directory:

```bash
cd backend
```

Create and activate a virtual environment:

```bash
python -m venv .venv
```

Install dependencies:

```bash
pip install fastapi uvicorn
```

Run FastAPI:

```bash
uvicorn main:app --reload
```

The backend will run locally on:

```text
http://localhost:8000
```

### Expose the Backend

For development, use **ngrok**:

```bash
ngrok http 8000
```

Copy the generated HTTPS URL and configure it as the Add-on backend URL.

> ngrok is used for development only.
> In production, the backend should be deployed to a persistent HTTPS environment.

### Gmail Add-on Setup

Create a new Google Apps Script project and add:

* [`Code.gs`](gmail-addon/Code.gs) – contains the Gmail Add-on logic, email extraction, backend request, UI rendering, and user actions.
* [`appsscript.json`](gmail-addon/appsscript.json) – contains the Gmail Add-on configuration, OAuth scopes, contextual trigger, and Gmail Advanced Service definition.

Then:

1. Create a Google Apps Script project.
2. Copy `gmail-addon/Code.gs` and `gmail-addon/appsscript.json` into it.
3. Enable the Gmail Advanced Service (already declared in `appsscript.json`, but it still needs to be turned on for the project in the Apps Script UI).
4. Set the backend URL - in `Code.gs`, update the `UrlFetchApp.fetch(...)` call in `analyzeMessage()` to point at your own backend (ngrok URL for development, or your deployed URL).
5. Deploy as a test deployment.
6. Open an email in Gmail and launch **Email Security Shield**.

> **Note:** `Code.gs` currently sends `sender`, `subject`, `body`, `links`, and `authentication` to the backend - it does not yet send `html` or `attachments`, so the `structure` and `attachments` analyzers won't produce signals until the Add-on is extended to include them.

---

## API Contract

### Request

`POST /api/v1/analyze`

```json
{
  "sender": {
    "name": "PayPal",
    "email": "support@paypa1.com"
  },
  "subject": "Urgent: Verify your account",
  "body": "Your account will be suspended...",
  "html": "",
  "links": [
    {
      "text": "paypal.com",
      "url": "https://paypa1.com/login"
    }
  ],
  "authentication": {
    "spf": "fail",
    "dkim": "pass",
    "dmarc": "fail"
  },
  "attachments": []
}
```

`html` and `attachments` are optional (default to `""` and `[]`); `links` and `authentication` are also optional.

### Response

```json
{
  "score": 100,
  "verdict": "High Risk",
  "recommendation": "Do not interact with this email: do not click any links or enter credentials. Report the email as phishing.",
  "base_score": 85,
  "category_raw_scores": {
    "identity": 25,
    "links": 25,
    "authentication": 26,
    "content": 43
  },
  "category_capped_scores": {
    "identity": 25,
    "links": 25,
    "authentication": 20,
    "content": 15
  },
  "combo_rules_applied": [
    { "name": "brand_impersonation_with_credential_request", "bonus": 12 },
    { "name": "brand_impersonation_with_link_mismatch", "bonus": 12 }
  ],
  "risk_floors_applied": [],
  "signals": [
    {
      "code": "lookalike_domain",
      "category": "identity",
      "reason": "Sender domain 'paypa1.com' impersonates 'paypal' but is not one of its known domains (paypal.com)",
      "points": 25
    },
    {
      "code": "link_domain_mismatch",
      "category": "links",
      "reason": "Displayed link domain 'paypal.com' does not match actual destination 'paypa1.com'",
      "points": 25
    }
  ]
}
```

(`signals` is truncated above for readability - the actual response for this request also includes `spf_fail`, `dmarc_fail`, `multiple_authentication_failures`, `urgency`, `threat`, `credential_request`, and `account_suspension`.)

`base_score` and `category_raw_scores` are diagnostic fields - they show the score *before* the 100-point cap is applied, which is why they can exceed the final `score`.

---

## Key Design Decisions

### Signals First, Scoring Second

Analyzers detect individual suspicious behaviors but do not make the final malicious/not-malicious decision.
The Scoring Engine is responsible for combining these signals. This keeps detection logic modular and makes scoring easier to tune independently.

### Explainability

The product does not only return a score. Each score is supported by clear findings that explain **why** the email was flagged.

### Deterministic MVP

For the MVP, I prioritized deterministic heuristics over adding unnecessary ML complexity.
This makes the system easier to understand, debug, and evaluate while leaving room for ML/LLM signals as an additional layer later.

### User-Focused Output

The UI is designed around three questions:

1. Is this email dangerous?
2. Why?
3. What should I do?

The result therefore focuses on the score, verdict, strongest signals, recommendation, and contextual actions.

---

## Known Limitations

* The detection logic is currently rule-based and may produce false positives or false negatives.
* The brand and URL-shortener knowledge base is not exhaustive.
* `Report Phishing` is currently an MVP feedback action rather than a full Gmail phishing-report integration.
* The current backend uses ngrok for development rather than a persistent deployment.
* Content-based heuristics currently have limited language coverage.
* The endpoint does not currently include application-level authentication.

---

## Testing

The backend can also be tested directly using a POST request:

```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "sender": {"name": "PayPal", "email": "support@paypa1.com"},
    "subject": "Urgent: Verify your account",
    "body": "Your account will be suspended...",
    "links": [{"text": "paypal.com", "url": "https://paypa1.com/login"}],
    "authentication": {"spf": "fail", "dkim": "pass", "dmarc": "fail"}
  }'
```

A successful response should contain:

```text
score
verdict
recommendation
signals
```

The complete flow can be verified by opening an email in Gmail and launching the Add-on.

---

## Future Improvements

With more time, I would:

* Tune scoring using labeled phishing and benign datasets.
* Expand brand and domain intelligence.
* Add ML/LLM-based signals as a secondary layer.
* Add automated tests and monitoring.
* Deploy the backend to a persistent cloud environment.
* Improve the visual identity and add a custom surfboard-based product logo.

---

## Product Review

Part 2 – Product Review:
`[Add link to Product Review document]`
