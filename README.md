# QueueStorm Warmup

QueueStorm Warmup is a FastAPI service that classifies a single customer support ticket into a ticket category, severity, handling department, human-review flag, and confidence score. It is designed for hackathon review: simple to understand, fast to run, and strict about the public API contract.

## Features

- Smart ticket classification
- English support
- Pure Bangla support
- Roman Bangla support
- Mixed-language support
- Locale-aware classification
- Dynamic confidence scoring
- Amount extraction
- Human review detection
- FastAPI
- OpenAPI documentation

## Project Structure

```text
TicketIQ/
├── app/
│   ├── __init__.py
│   ├── classifier.py
│   └── main.py
├── tests/
│   └── test_classifier.py
├── Dockerfile
├── requirements.txt
└── README.md
```

### Important files

- [app/main.py](app/main.py) contains the FastAPI app, request and response models, endpoint handlers, and the minimal validation layer.
- [app/classifier.py](app/classifier.py) contains the ticket normalization, pattern matching, scoring, confidence logic, summary generation, and language handling.
- [tests/test_classifier.py](tests/test_classifier.py) contains unit tests for the contest examples, language coverage, negation handling, amount extraction, and API behavior.
- [requirements.txt](requirements.txt) pins the Python dependencies required to run the service.
- [Dockerfile](Dockerfile) packages the app for container deployment.

## Installation

### 1. Clone the repository

```bash
git clone <your-repository-url>
cd TicketIQ
```

### 2. Create a virtual environment

```bash
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the application

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Running

Start the server with:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Then open:

- http://127.0.0.1:8000/health
- http://127.0.0.1:8000/docs
- http://127.0.0.1:8000/redoc

## API Documentation

FastAPI automatically exposes interactive API docs:

- `/docs` for Swagger UI
- `/redoc` for ReDoc

After the server starts, open `http://127.0.0.1:8000/docs` or `http://127.0.0.1:8000/redoc` in your browser.

## Endpoints

### `GET /health`

Returns a simple health check response.

#### Example response

```json
{
  "status": "ok"
}
```

### `POST /sort-ticket`

Accepts one ticket and returns a structured classification.

#### Request example

```json
{
  "ticket_id": "T-001",
  "channel": "app",
  "locale": "en",
  "message": "I sent 5000 taka to a wrong number this morning, please help me get it back"
}
```

#### Response example

```json
{
  "ticket_id": "T-001",
  "case_type": "wrong_transfer",
  "severity": "high",
  "department": "dispute_resolution",
  "agent_summary": "Customer reports sending 5000 BDT to the wrong recipient and requests recovery.",
  "human_review_required": false,
  "confidence": 0.97
}
```

## Classification Categories

### `case_type`

| Value | Meaning |
| --- | --- |
| `wrong_transfer` | Money was sent to the wrong recipient or account |
| `payment_failed` | A payment or transaction failed, or money was deducted without completion |
| `refund_request` | The customer is asking for a refund or reversal |
| `phishing_or_social_engineering` | The ticket mentions OTP, PIN, password, or suspicious contact attempts |
| `other` | Anything that does not fit the supported categories |

### `severity`

| Value | Meaning |
| --- | --- |
| `low` | Low urgency or general support issue |
| `medium` | Needs attention, but not urgent |
| `high` | Important financial or dispute issue |
| `critical` | Potential fraud or immediate human review required |

### `department`

| Value | Typical use |
| --- | --- |
| `customer_support` | General support or refund requests |
| `dispute_resolution` | Wrong transfer cases |
| `payments_ops` | Payment failures |
| `fraud_risk` | Phishing or social-engineering cases |

## Language Support

The classifier supports English, Pure Bangla, Roman Bangla, and mixed-language text.

### English

- `I sent money to the wrong number.`
- `Payment failed but money was deducted.`
- `Please refund my transaction.`

### Pure Bangla

- `আমি ভুল নাম্বারে টাকা পাঠিয়েছি।`
- `লেনদেন ব্যর্থ হয়েছে কিন্তু টাকা কেটে নিয়েছে।`
- `আমি রিফান্ড চাই।`

### Roman Bangla

- `ami vul number e taka pathaisi`
- `taka kete niyse`
- `otp chaise`
- `refund chai`

### Mixed Language

- `Wrong number e taka pathaisi`
- `আমাকে OTP দিতে বলেছে`
- `Payment failed but refund chai`

## Example Requests

The following examples reflect realistic support tickets and the expected classification direction.

| # | Request message | Expected case_type |
| --- | --- | --- |
| 1 | `I sent money to wrong number` | `wrong_transfer` |
| 2 | `I accidentally transferred money` | `wrong_transfer` |
| 3 | `Payment failed but money deducted` | `payment_failed` |
| 4 | `Please refund my transaction` | `refund_request` |
| 5 | `Someone asked my OTP` | `phishing_or_social_engineering` |
| 6 | `App crashes on startup` | `other` |
| 7 | `আমি ভুল নাম্বারে টাকা পাঠিয়েছি` | `wrong_transfer` |
| 8 | `লেনদেন ব্যর্থ হয়েছে কিন্তু টাকা কেটে নিয়েছে` | `payment_failed` |
| 9 | `ami vul account e taka pathaisi` | `wrong_transfer` |
| 10 | `Wrong number e taka pathaisi and someone asked for OTP` | `phishing_or_social_engineering` |

## Example Responses

### Wrong transfer

```json
{
  "ticket_id": "T-001",
  "case_type": "wrong_transfer",
  "severity": "high",
  "department": "dispute_resolution",
  "agent_summary": "Customer reports sending 5000 BDT to the wrong recipient and requests recovery.",
  "human_review_required": false,
  "confidence": 0.97
}
```

### Payment failed

```json
{
  "ticket_id": "T-002",
  "case_type": "payment_failed",
  "severity": "high",
  "department": "payments_ops",
  "agent_summary": "Customer reports a failed payment where 5000 BDT was deducted but the transaction did not complete.",
  "human_review_required": false,
  "confidence": 0.98
}
```

### Phishing or social engineering

```json
{
  "ticket_id": "T-003",
  "case_type": "phishing_or_social_engineering",
  "severity": "critical",
  "department": "fraud_risk",
  "agent_summary": "Customer reports a suspicious request involving account credentials and requires immediate review.",
  "human_review_required": true,
  "confidence": 0.99
}
```

## Classification Logic

The classifier is rule-based and optimized for fast, deterministic behavior.

- Normalization: text is normalized once using Unicode-aware cleanup, lowercase folding, and whitespace normalization.
- Regex matching: compiled patterns are reused instead of being rebuilt per request.
- Weighted scoring: each category accumulates weighted matches, then the best score wins.
- Severity selection: severity is derived from the winning category and score thresholds.
- Confidence calculation: confidence uses score, margin to the second-best category, severity, matched rules, and locale hints.
- Human review logic: any critical case or phishing case is automatically marked for human review.

## Deployment

### Render

- Create a new Web Service.
- Connect the public GitHub repository.
- Use the build command `pip install -r requirements.txt`.
- Use the start command `uvicorn app.main:app --host 0.0.0.0 --port $PORT`.

### Railway

- Create a new project from GitHub.
- Set the start command to `uvicorn app.main:app --host 0.0.0.0 --port $PORT`.
- Railway will provide an HTTPS URL for the live API.

### Docker

Build and run the container locally or in production:

```bash
docker build -t queuestorm-warmup .
docker run -p 8000:8000 queuestorm-warmup
```

## Development

### Run locally

```bash
.venv\Scripts\activate
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Format code

This project is intentionally small and uses standard Python formatting conventions. If you introduce a formatter, apply it consistently across the repository.

### Test

```bash
python -m unittest discover -s tests -p "test_*.py"
```

## Performance

- Compiled regex keeps classification fast.
- Text is normalized once per ticket.
- The service has no GPU dependency.
- The service has no external AI dependency.
- The implementation is lightweight enough to respond quickly under normal hackathon traffic.

## Security

- No OTP exposure in summaries.
- No PIN exposure in summaries.
- No password exposure in summaries.
- No secret logging.
- No code execution on user input.

## Future Improvements

- Add more Bangla spelling variants and transliteration coverage.
- Expand the rule set with more production ticket samples.
- Add structured metrics for category frequency and review rates.
- Add CI checks for tests and formatting.
- Add a persistent `LICENSE` file and release metadata.

## License

MIT License.

