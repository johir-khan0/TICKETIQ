from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from time import perf_counter
from typing import Literal

from dotenv import load_dotenv
from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from pydantic import ValidationError
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.classifier import analyze_ticket


load_dotenv()


logger = logging.getLogger("ticketiq.api")


def _get_env(name: str, default: str) -> str:
    value = os.getenv(name, "").strip()
    return value or default


def _split_csv_env(name: str, default: list[str]) -> list[str]:
    raw_value = os.getenv(name, "").strip()
    if not raw_value:
        return default

    values = [item.strip() for item in raw_value.split(",") if item.strip()]
    return values or default


def _parse_int_env(name: str, default: int) -> int:
    raw_value = os.getenv(name, "").strip()
    if not raw_value:
        return default

    try:
        return int(raw_value)
    except ValueError:
        return default


APP_NAME = _get_env("APP_NAME", "QueueStorm Warmup API")
APP_VERSION = _get_env("APP_VERSION", "1.0.0")
APP_ENV = _get_env("APP_ENV", "development")
APP_SUMMARY = _get_env("APP_SUMMARY", "Classify one customer support ticket into a structured triage response.")
APP_CONTACT_NAME = _get_env("APP_CONTACT_NAME", "QueueStorm Warmup Maintainers")
APP_CONTACT_URL = _get_env("APP_CONTACT_URL", "https://github.com/")
APP_LICENSE_NAME = _get_env("APP_LICENSE_NAME", "MIT License")
APP_LICENSE_IDENTIFIER = _get_env("APP_LICENSE_IDENTIFIER", "MIT")
RATE_LIMIT_HEALTH = _get_env("RATE_LIMIT_HEALTH", "60/minute")
RATE_LIMIT_SORT = _get_env("RATE_LIMIT_SORT", "30/minute")
MAX_REQUEST_BODY_BYTES = _parse_int_env("MAX_REQUEST_BODY_BYTES", 16_384)

DEFAULT_ALLOWED_HOSTS = ["localhost", "127.0.0.1", "testserver", "*.onrender.com", "*.railway.app"]
DEFAULT_ALLOWED_ORIGINS = ["http://localhost", "http://127.0.0.1", "http://localhost:3000", "http://127.0.0.1:3000"]

ALLOWED_HOSTS = _split_csv_env("ALLOWED_HOSTS", DEFAULT_ALLOWED_HOSTS)
ALLOWED_ORIGINS = _split_csv_env("ALLOWED_ORIGINS", DEFAULT_ALLOWED_ORIGINS)


limiter = Limiter(key_func=get_remote_address, default_limits=[])


def _error_response(status_code: int, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": True, "message": message, "status_code": status_code},
    )


def _security_headers() -> dict[str, str]:
    return {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Cache-Control": "no-store, max-age=0",
    }


def _client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    if forwarded_for:
        return forwarded_for
    if request.client and request.client.host:
        return request.client.host
    return "-"


class RequestBodyLimitMiddleware:
    def __init__(self, app: object, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: dict, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        content_length = None
        for header_name, header_value in scope.get("headers", []):
            if header_name.lower() == b"content-length":
                try:
                    content_length = int(header_value.decode("latin-1"))
                except ValueError:
                    content_length = None
                break

        if content_length is not None and content_length > self.max_bytes:
            await _error_response(413, "Request body is too large.")(scope, receive, send)
            return

        await self.app(scope, receive, send)


Channel = Literal["app", "sms", "call_center", "merchant_portal"]
Locale = Literal["bn", "en", "mixed"]
CaseType = Literal[
    "wrong_transfer",
    "payment_failed",
    "refund_request",
    "phishing_or_social_engineering",
    "other",
]
Severity = Literal["low", "medium", "high", "critical"]
Department = Literal[
    "customer_support",
    "dispute_resolution",
    "payments_ops",
    "fraud_risk",
]


tags_metadata = [
    {
        "name": "Health",
        "description": "Operational endpoints used to verify that the service is healthy and reachable.",
    },
    {
        "name": "Ticket Classification",
        "description": "Endpoints that classify a single customer ticket into a structured triage response.",
    },
]

app = FastAPI(
    title=APP_NAME,
    summary=APP_SUMMARY,
    description=(
        "QueueStorm Warmup is a lightweight FastAPI ticket triage service for hackathon review and deployment. "
        "It accepts one support ticket, applies the internal classifier, and returns the category, severity, owning department, "
        "human-review flag, and a concise agent summary. The API supports English, Pure Bangla, Roman Bangla, and mixed-language input, "
        "and is documented with examples for Swagger UI and ReDoc."
    ),
    version=APP_VERSION,
    contact={
        "name": APP_CONTACT_NAME,
        "url": APP_CONTACT_URL,
    },
    license_info={
        "name": APP_LICENSE_NAME,
        "identifier": APP_LICENSE_IDENTIFIER,
    },
    openapi_tags=tags_metadata,
)

app.state.limiter = limiter
app.add_middleware(RequestBodyLimitMiddleware, max_bytes=MAX_REQUEST_BODY_BYTES)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


class HealthResponse(BaseModel):
    status: str = Field(
        description="Health status of the API.",
        example="ok",
    )
    service: str = Field(
        description="Public service name returned by the health endpoint.",
        example=APP_NAME,
    )
    version: str = Field(
        description="Published service version.",
        example=APP_VERSION,
    )
    environment: str = Field(
        description="Runtime environment name.",
        example=APP_ENV,
    )
    timestamp: str = Field(
        description="UTC timestamp in ISO 8601 format.",
        example="2026-06-26T00:00:00Z",
    )


class ErrorResponse(BaseModel):
    error: bool = Field(
        description="Indicates that the response is an error envelope.",
        example=True,
    )
    message: str = Field(
        description="Human-readable error message.",
        example="Validation failed.",
    )
    status_code: int = Field(
        description="HTTP status code for the error.",
        example=422,
    )


@app.middleware("http")
async def log_and_secure_responses(request: Request, call_next):
    start_time = perf_counter()
    response = await call_next(request)

    for header_name, header_value in _security_headers().items():
        response.headers[header_name] = header_value

    processing_time_ms = (perf_counter() - start_time) * 1000
    logger.info(
        "%s %s status=%s duration_ms=%.2f client_ip=%s",
        request.method,
        request.url.path,
        response.status_code,
        processing_time_ms,
        _client_ip(request),
    )
    return response


async def _http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    return _error_response(exc.status_code, str(exc.detail))


async def _request_validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    return _error_response(422, "Validation failed.")


async def _pydantic_validation_exception_handler(request: Request, exc: ValidationError) -> JSONResponse:
    return _error_response(422, "Validation failed.")


async def _rate_limit_exception_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    return _error_response(429, "Rate limit exceeded. Please try again later.")


async def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return _error_response(500, "Internal server error.")


app.add_exception_handler(HTTPException, _http_exception_handler)
app.add_exception_handler(RequestValidationError, _request_validation_exception_handler)
app.add_exception_handler(ValidationError, _pydantic_validation_exception_handler)
app.add_exception_handler(RateLimitExceeded, _rate_limit_exception_handler)
app.add_exception_handler(Exception, _unhandled_exception_handler)


class TicketIn(BaseModel):
    ticket_id: str = Field(
        min_length=1,
        max_length=64,
        description="Unique CRM or support ticket identifier that will be echoed back in the response.",
        example="T-001",
        examples=["T-001"],
    )
    channel: Channel | None = Field(
        default=None,
        description="Optional source channel where the ticket was created.",
        example="app",
        examples=["app"],
    )
    locale: Locale | None = Field(
        default=None,
        description="Optional locale hint for language-aware classification.",
        example="en",
        examples=["en"],
    )
    message: str = Field(
        min_length=1,
        max_length=4000,
        description="Free-text customer complaint or support message to classify.",
        example="I sent 5000 taka to a wrong number this morning, please help me get it back.",
        examples=["I sent 5000 taka to a wrong number this morning, please help me get it back."],
    )

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "summary": "English wrong transfer",
                    "value": {
                        "ticket_id": "T-001",
                        "channel": "app",
                        "locale": "en",
                        "message": "I sent money to the wrong number.",
                    },
                },
                {
                    "summary": "Pure Bangla wrong transfer",
                    "value": {
                        "ticket_id": "T-002",
                        "channel": "sms",
                        "locale": "bn",
                        "message": "আমি ভুল নাম্বারে টাকা পাঠিয়েছি।",
                    },
                },
                {
                    "summary": "Roman Bangla wrong transfer",
                    "value": {
                        "ticket_id": "T-003",
                        "channel": "call_center",
                        "locale": "mixed",
                        "message": "ami vul number e taka pathaisi",
                    },
                },
                {
                    "summary": "Mixed language payment failure",
                    "value": {
                        "ticket_id": "T-004",
                        "channel": "app",
                        "locale": "mixed",
                        "message": "Payment failed but টাকা কেটে নিয়েছে.",
                    },
                },
                {
                    "summary": "Refund request",
                    "value": {
                        "ticket_id": "T-005",
                        "channel": "merchant_portal",
                        "locale": "en",
                        "message": "Please refund my transaction.",
                    },
                },
                {
                    "summary": "Phishing request",
                    "value": {
                        "ticket_id": "T-006",
                        "channel": "sms",
                        "locale": "en",
                        "message": "Someone asked my OTP and PIN.",
                    },
                },
                {
                    "summary": "Other issue",
                    "value": {
                        "ticket_id": "T-007",
                        "channel": "app",
                        "locale": "en",
                        "message": "The app crashes on startup.",
                    },
                },
                {
                    "summary": "Bangla refund request",
                    "value": {
                        "ticket_id": "T-008",
                        "channel": "app",
                        "locale": "bn",
                        "message": "আমি রিফান্ড চাই।",
                    },
                },
                {
                    "summary": "Bangla phishing request",
                    "value": {
                        "ticket_id": "T-009",
                        "channel": "sms",
                        "locale": "bn",
                        "message": "আমাকে ওটিপি দিতে বলেছে।",
                    },
                },
                {
                    "summary": "Roman Bangla payment failure",
                    "value": {
                        "ticket_id": "T-010",
                        "channel": "app",
                        "locale": "mixed",
                        "message": "taka kete niyse but payment fail hoye geche",
                    },
                },
            ]
        },
    )


class TicketOut(BaseModel):
    ticket_id: str = Field(
        description="Ticket identifier echoed from the request.",
        example="T-001",
        examples=["T-001"],
    )
    case_type: CaseType = Field(
        description="Normalized ticket category returned by the classifier.",
        example="wrong_transfer",
        examples=["wrong_transfer"],
    )
    severity: Severity = Field(
        description="Urgency level used for triage and escalation.",
        example="high",
        examples=["high"],
    )
    department: Department = Field(
        description="Owning internal team that should handle the ticket.",
        example="dispute_resolution",
        examples=["dispute_resolution"],
    )
    agent_summary: str = Field(
        description="Concise one- or two-sentence summary for a human agent.",
        example="Customer reports sending 5000 BDT to the wrong recipient and requests recovery.",
        examples=["Customer reports sending 5000 BDT to the wrong recipient and requests recovery."],
    )
    human_review_required: bool = Field(
        description="True when the ticket is critical or indicates phishing or social engineering.",
        example=False,
        examples=[False],
    )
    confidence: float = Field(
        description="Classifier confidence score between 0.50 and 0.99.",
        example=0.97,
        examples=[0.97],
    )


@app.get(
    "/health",
    tags=["Health"],
    summary="Check service health",
    description="Returns the service status, version, environment, and a UTC timestamp for operational checks.",
    response_description="A status payload describing the current runtime state of the API.",
    response_model=HealthResponse,
    responses={
        200: {
            "description": "Service is healthy.",
            "content": {
                "application/json": {
                    "example": {
                        "status": "ok",
                        "service": APP_NAME,
                        "version": APP_VERSION,
                        "environment": APP_ENV,
                        "timestamp": "2026-06-26T00:00:00Z",
                    }
                }
            },
        },
        400: {
            "description": "Bad request. Included for completeness in the published API documentation.",
            "content": {"application/json": {"example": {"error": True, "message": "Bad request.", "status_code": 400}}},
        },
        422: {
            "description": "Validation error returned when the request cannot be parsed by FastAPI or Pydantic.",
            "content": {"application/json": {"example": {"error": True, "message": "Validation failed.", "status_code": 422}}},
        },
        429: {
            "description": "Rate limit exceeded for the requesting IP address.",
            "content": {"application/json": {"example": {"error": True, "message": "Rate limit exceeded. Please try again later.", "status_code": 429}}},
        },
        500: {
            "description": "Unexpected server-side error.",
            "content": {"application/json": {"example": {"error": True, "message": "Internal server error.", "status_code": 500}}},
        },
    },
)
@limiter.limit(RATE_LIMIT_HEALTH)
def health(request: Request) -> HealthResponse:
    return HealthResponse(
        status="ok",
        service=APP_NAME,
        version=APP_VERSION,
        environment=APP_ENV,
        timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    )


@app.post(
    "/sort-ticket",
    tags=["Ticket Classification"],
    summary="Classify a single support ticket",
    description=(
        "Accepts one customer support ticket, analyzes the message with the internal classifier, and returns a "
        "structured triage response containing the case type, severity, department, summary, human-review flag, and confidence. "
        "The workflow supports English, Pure Bangla, Roman Bangla, and mixed-language text."
    ),
    response_description="A structured classification response ready for agent triage.",
    response_model=TicketOut,
    responses={
        200: {
            "description": "Ticket classified successfully.",
            "content": {
                "application/json": {
                    "examples": {
                        "wrong_transfer": {
                            "summary": "Wrong transfer response",
                            "value": {
                                "ticket_id": "T-001",
                                "case_type": "wrong_transfer",
                                "severity": "high",
                                "department": "dispute_resolution",
                                "agent_summary": "Customer reports sending 5000 BDT to the wrong recipient and requests recovery.",
                                "human_review_required": False,
                                "confidence": 0.97,
                            },
                        },
                        "payment_failed": {
                            "summary": "Payment failed response",
                            "value": {
                                "ticket_id": "T-002",
                                "case_type": "payment_failed",
                                "severity": "high",
                                "department": "payments_ops",
                                "agent_summary": "Customer reports a failed payment where 5000 BDT was deducted but the transaction did not complete.",
                                "human_review_required": False,
                                "confidence": 0.98,
                            },
                        },
                        "refund_request": {
                            "summary": "Refund request response",
                            "value": {
                                "ticket_id": "T-003",
                                "case_type": "refund_request",
                                "severity": "low",
                                "department": "customer_support",
                                "agent_summary": "Customer is requesting a refund for 5000 BDT.",
                                "human_review_required": False,
                                "confidence": 0.95,
                            },
                        },
                        "phishing": {
                            "summary": "Phishing response",
                            "value": {
                                "ticket_id": "T-004",
                                "case_type": "phishing_or_social_engineering",
                                "severity": "critical",
                                "department": "fraud_risk",
                                "agent_summary": "Customer reports a suspicious request involving account credentials and requires immediate review.",
                                "human_review_required": True,
                                "confidence": 0.99,
                            },
                        },
                        "other": {
                            "summary": "Other issue response",
                            "value": {
                                "ticket_id": "T-005",
                                "case_type": "other",
                                "severity": "low",
                                "department": "customer_support",
                                "agent_summary": "Customer reports an issue that needs manual triage.",
                                "human_review_required": False,
                                "confidence": 0.62,
                            },
                        },
                    }
                }
            },
        },
        400: {
            "description": "Bad request. Included for completeness in the published API documentation.",
            "content": {"application/json": {"example": {"error": True, "message": "Bad request.", "status_code": 400}}},
        },
        422: {
            "description": "Validation error returned when the request cannot be parsed by FastAPI or Pydantic.",
            "content": {"application/json": {"example": {"error": True, "message": "Validation failed.", "status_code": 422}}},
        },
        429: {
            "description": "Rate limit exceeded for the requesting IP address.",
            "content": {"application/json": {"example": {"error": True, "message": "Rate limit exceeded. Please try again later.", "status_code": 429}}},
        },
        500: {
            "description": "Unexpected server-side error.",
            "content": {"application/json": {"example": {"error": True, "message": "Internal server error.", "status_code": 500}}},
        },
    },
)
@limiter.limit(RATE_LIMIT_SORT)
def sort_ticket(request: Request, ticket: TicketIn = Body(...)) -> TicketOut:
    ticket_id = ticket.ticket_id.strip()
    message = ticket.message.strip()

    if not ticket_id:
        raise HTTPException(status_code=422, detail="ticket_id must not be empty")
    if not message:
        raise HTTPException(status_code=422, detail="message must not be empty")

    analysis = analyze_ticket(message, ticket.locale)
    return TicketOut(
        ticket_id=ticket_id,
        case_type=analysis.case_type,
        severity=analysis.severity,
        department=analysis.department,
        agent_summary=analysis.agent_summary,
        human_review_required=analysis.human_review_required,
        confidence=analysis.confidence,
    )
