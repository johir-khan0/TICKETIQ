from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Literal


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
LocaleHint = Literal["bn", "en", "mixed"]
RuleLanguage = Literal["en", "bn", "roman", "shared"]

MIN_CONFIDENCE = 0.50
MAX_CONFIDENCE = 0.99

CASE_TO_DEPARTMENT: dict[CaseType, Department] = {
    "wrong_transfer": "dispute_resolution",
    "payment_failed": "payments_ops",
    "refund_request": "customer_support",
    "phishing_or_social_engineering": "fraud_risk",
    "other": "customer_support",
}

CASE_TO_BASE_SEVERITY: dict[CaseType, Severity] = {
    "wrong_transfer": "high",
    "payment_failed": "high",
    "refund_request": "low",
    "phishing_or_social_engineering": "critical",
    "other": "low",
}

CASE_PRIORITY: dict[CaseType, int] = {
    "phishing_or_social_engineering": 4,
    "wrong_transfer": 3,
    "payment_failed": 2,
    "refund_request": 1,
    "other": 0,
}

SEVERITY_RANK: dict[Severity, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SEVERITY_THRESHOLDS: dict[CaseType, tuple[tuple[int, Severity], ...]] = {
    "wrong_transfer": ((14, "critical"), (0, "high")),
    "payment_failed": ((14, "critical"), (0, "high")),
    "refund_request": ((12, "high"), (8, "medium"), (0, "low")),
    "phishing_or_social_engineering": ((0, "critical"),),
    "other": ((0, "low"),),
}

LOCALE_WEIGHT: dict[str, dict[RuleLanguage, float]] = {
    "bn": {"bn": 1.30, "roman": 1.15, "en": 0.90, "shared": 1.05},
    "en": {"en": 1.25, "roman": 1.05, "bn": 0.85, "shared": 1.00},
    "mixed": {"en": 1.10, "bn": 1.10, "roman": 1.10, "shared": 1.00},
}

NEGATION_MARKERS = re.compile(
    r"\b(?:not|never|didn['’]?t|did not|no one|nobody|don['’]?t|doesn['’]?t|won['’]?t|can't|cannot|না|নেই|দিইনি|দেইনি|করিনি|হয়নি|হয়নি)\b",
    re.IGNORECASE,
)
BANGLA_SCRIPT = re.compile(r"[\u0980-\u09FF]")
LATIN_SCRIPT = re.compile(r"[A-Za-z]")

MULTISPACE_PATTERN = re.compile(r"\s+")
NUMBER_PATTERN = re.compile(
    r"(?:৳\s*)?(?P<number>(?:\d{1,3}(?:[\s,]\d{3})+|\d+|[০-৯]+))(?:\s*(?P<unit>k|thousand|হাজার))?(?:\s*(?:bdt|tk|taka))?",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Rule:
    case_type: CaseType
    pattern: re.Pattern[str]
    weight: int
    language: RuleLanguage
    negation_sensitive: bool = False


@dataclass(frozen=True)
class CaseScore:
    case_type: CaseType
    score: int
    matched_rules: int


@dataclass(frozen=True)
class TicketAnalysis:
    case_type: CaseType
    severity: Severity
    department: Department
    agent_summary: str
    human_review_required: bool
    confidence: float
    amount: str | None
    detected_locale: str
    top_score: int
    second_score: int
    matched_rules: int


def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


RULES: tuple[Rule, ...] = (
    Rule("wrong_transfer", _compile(r"\bwrong\s+(?:number|no\.?|account|recipient|person)\b"), 5, "en"),
    Rule("wrong_transfer", _compile(r"\b(?:incorrect|mistaken)\s+(?:number|account|recipient)\b"), 4, "en"),
    Rule("wrong_transfer", _compile(r"\baccidentally\s+(?:sent|transferred)\b"), 4, "en"),
    Rule("wrong_transfer", _compile(r"\bsent\s+money\s+to\s+the\s+wrong\b"), 5, "en"),
    Rule("wrong_transfer", _compile(r"\btransfer(?:red)?\s+(?:to\s+)?(?:the\s+)?wrong\b"), 4, "en"),
    Rule("wrong_transfer", _compile(r"\b(?:wrong|incorrect)\s+(?:recipient|account|number)\b"), 5, "en"),
    Rule("wrong_transfer", _compile(r"\b(?:vul|bhul|vule)\b(?:\s+\w+){0,3}\s+(?:number|nambar|nomber|account|recipient|acc(?:ount)?)\b"), 5, "roman"),
    Rule("wrong_transfer", _compile(r"\b(?:taka|tk)\s+(?:pathaisi|pathayechi|pathalam|pathaisi?o|pathaiya|pathaisi)\b"), 4, "roman"),
    Rule("wrong_transfer", _compile(r"ভুল\s+(?:নাম্বার|নম্বরে?|নম্বর|অ্যাকাউন্ট|একাউন্ট|প্রাপক|ব্যক্তি)\b"), 5, "bn"),
    Rule("wrong_transfer", _compile(r"অন্য\s+(?:নম্বর|অ্যাকাউন্টে?|একাউন্টে?|প্রাপকে?)\b"), 4, "bn"),
    Rule("wrong_transfer", _compile(r"ভুলে(?:\s+\w+){0,3}\s+(?:পাঠিয়েছি|পাঠিয়েছি|পাঠাইছি|পাঠাইসি|পাঠালাম|পাঠিয়াছি)\b"), 4, "bn"),
    Rule("wrong_transfer", _compile(r"ভুলে\s+অন্য\s+অ্যাকাউন্টে\s+টাকা\s+চলে\s+গেছে\b"), 6, "bn"),
    Rule("payment_failed", _compile(r"\bpayment\s+failed\b"), 5, "en"),
    Rule("payment_failed", _compile(r"\btransaction\s+failed\b"), 5, "en"),
    Rule("payment_failed", _compile(r"\bpayment\s+unsuccessful\b"), 4, "en"),
    Rule("payment_failed", _compile(r"\btransaction\s+unsuccessful\b"), 4, "en"),
    Rule("payment_failed", _compile(r"\b(?:money|balance|amount)\s+deducted\b"), 5, "en"),
    Rule("payment_failed", _compile(r"\bdebited\b"), 3, "en"),
    Rule("payment_failed", _compile(r"\bpending\b"), 3, "en"),
    Rule("payment_failed", _compile(r"\bprocessing\b"), 2, "en"),
    Rule("payment_failed", _compile(r"\bstuck\b"), 2, "en"),
    Rule("payment_failed", _compile(r"\brefund\s+not\s+received\b"), 3, "en"),
    Rule("payment_failed", _compile(r"\bpayment\s+fail(?:ed|s)?\b"), 4, "roman"),
    Rule("payment_failed", _compile(r"\btransaction\s+fail(?:ed|s)?\b"), 4, "roman"),
    Rule("payment_failed", _compile(r"\btaka\s+kete\s+(?:niyse|niyeche|nise|niseche|niyechhe|gese|geseche)\b"), 5, "roman"),
    Rule("payment_failed", _compile(r"লেনদেন\s+ব্যর্থ\b"), 5, "bn"),
    Rule("payment_failed", _compile(r"পেমেন্ট\s+ব্যর্থ\b"), 5, "bn"),
    Rule("payment_failed", _compile(r"টাকা\s+কেটে\s+(?:নিয়েছে|নিয়েছে|গেছে|গিয়েছে|গিয়েছে)\b"), 5, "bn"),
    Rule("refund_request", _compile(r"\brefund\b"), 5, "en"),
    Rule("refund_request", _compile(r"\bplease\s+refund\b"), 5, "en"),
    Rule("refund_request", _compile(r"\breturn\s+money\b"), 4, "en"),
    Rule("refund_request", _compile(r"\bmoney\s+back\b"), 4, "en"),
    Rule("refund_request", _compile(r"\breimburse\b"), 3, "en"),
    Rule("refund_request", _compile(r"\breverse\s+payment\b"), 4, "en"),
    Rule("refund_request", _compile(r"\bchargeback\b"), 4, "en"),
    Rule("refund_request", _compile(r"\brefund\s+chai\b"), 5, "roman"),
    Rule("refund_request", _compile(r"\btaka\s+ferot\s+chai\b"), 5, "roman"),
    Rule("refund_request", _compile(r"\bferot\s+chai\b"), 4, "roman"),
    Rule("refund_request", _compile(r"রিফান্ড\b"), 5, "bn"),
    Rule("refund_request", _compile(r"ফেরত\s+চাই\b"), 5, "bn"),
    Rule("refund_request", _compile(r"টাকা\s+ফেরত\b"), 5, "bn"),
    Rule("refund_request", _compile(r"ফেরত\s+দিন\b"), 4, "bn"),
    Rule("phishing_or_social_engineering", _compile(r"\b(?:share|send|give)\s+(?:my\s+)?(?:otp|pin|password|code)\b"), 5, "en", True),
    Rule("phishing_or_social_engineering", _compile(r"\b(?:asked|ask(?:ing)?|requested)\s+(?:for\s+)?(?:my\s+)?(?:otp|pin|password|code)\b"), 5, "en"),
    Rule("phishing_or_social_engineering", _compile(r"\botp\b"), 3, "en", True),
    Rule("phishing_or_social_engineering", _compile(r"\bpin\b"), 3, "en", True),
    Rule("phishing_or_social_engineering", _compile(r"\bpassword\b"), 3, "en", True),
    Rule("phishing_or_social_engineering", _compile(r"\bverification\s+code\b"), 4, "en", True),
    Rule("phishing_or_social_engineering", _compile(r"\bsecurity\s+code\b"), 4, "en", True),
    Rule("phishing_or_social_engineering", _compile(r"\bfake\s+(?:call|sms)\b"), 4, "en"),
    Rule("phishing_or_social_engineering", _compile(r"\bunknown\s+caller\b"), 4, "en"),
    Rule("phishing_or_social_engineering", _compile(r"\bscam(?:mer|)?\b"), 4, "shared"),
    Rule("phishing_or_social_engineering", _compile(r"\bfraud\b"), 4, "shared"),
    Rule("phishing_or_social_engineering", _compile(r"\bprotarok\b"), 4, "roman"),
    Rule("phishing_or_social_engineering", _compile(r"\botp\s*(?:chaise|dise|chay|chailo)\b"), 5, "roman"),
    Rule("phishing_or_social_engineering", _compile(r"\bpin\s*(?:chaise|dise|chay|chailo)\b"), 5, "roman"),
    Rule("phishing_or_social_engineering", _compile(r"\bpassword\s*(?:chaise|dise|chay|chailo)\b"), 5, "roman"),
    Rule("phishing_or_social_engineering", _compile(r"\b(?:otp|pin|password)\s+de(?:i|ye|i nai|ini|ina|a)?\b"), 4, "roman"),
    Rule("phishing_or_social_engineering", _compile(r"ওটিপি\b"), 5, "bn", True),
    Rule("phishing_or_social_engineering", _compile(r"পিন\b"), 5, "bn", True),
    Rule("phishing_or_social_engineering", _compile(r"পাসওয়ার্ড\b"), 5, "bn", True),
    Rule("phishing_or_social_engineering", _compile(r"পাসওয়ার্ড\b"), 5, "bn", True),
    Rule("phishing_or_social_engineering", _compile(r"(?:ওটিপি|পিন|পাসওয়ার্ড|পাসওয়ার্ড)\s+(?:দিতে|দেতে)\b"), 5, "bn", True),
    Rule("phishing_or_social_engineering", _compile(r"(?:ওটিপি|পিন|পাসওয়ার্ড|পাসওয়ার্ড)\s+(?:দিতে|দেতে)\s+বলেছে\b"), 5, "bn", True),
    Rule("phishing_or_social_engineering", _compile(r"(?:ওটিপি|পিন|পাসওয়ার্ড|পাসওয়ার্ড).{0,12}বলেছে"), 5, "bn", True),
    Rule("phishing_or_social_engineering", _compile(r"\b(?:ওটিপি|পিন|পাসওয়ার্ড|পাসওয়ার্ড)\b(?:\s+\w+){0,3}\s+(?:দিতে|দেতে|চাইতে|বলেছে|চাইছে|দিছে|দিছো|দিয়েছ|দিতেছে)\b"), 5, "bn"),
    Rule("phishing_or_social_engineering", _compile(r"ভেরিফিকেশন\s+কোড\b"), 4, "bn", True),
    Rule("phishing_or_social_engineering", _compile(r"সিকিউরিটি\s+কোড\b"), 4, "bn", True),
    Rule("phishing_or_social_engineering", _compile(r"ফেক\s+(?:কল|এসএমএস)\b"), 4, "bn"),
    Rule("phishing_or_social_engineering", _compile(r"অজানা\s+কলার\b"), 4, "bn"),
    Rule("phishing_or_social_engineering", _compile(r"স্ক্যাম\b"), 4, "bn"),
    Rule("phishing_or_social_engineering", _compile(r"জালিয়াতি\b"), 4, "bn"),
    Rule("phishing_or_social_engineering", _compile(r"প্রতারক\b"), 4, "bn"),
    Rule("phishing_or_social_engineering", _compile(r"প্রতারণা\b"), 4, "bn"),
)


def normalize_text(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text).casefold()
    normalized = normalized.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    normalized = "".join(
        char if (unicodedata.category(char)[0] in {"L", "M", "N"} or char.isspace() or char == "৳") else " "
        for char in normalized
    )
    return MULTISPACE_PATTERN.sub(" ", normalized).strip()


def matches_pattern(text: str, pattern: re.Pattern[str]) -> bool:
    return pattern.search(text) is not None


def _is_negated(text: str, start: int, end: int) -> bool:
    window_start = max(0, start - 40)
    window_end = min(len(text), end + 24)
    window = text[window_start:window_end]
    return NEGATION_MARKERS.search(window) is not None


def _locale_bonus(locale_hint: LocaleHint | None, detected_locale: str, rule_language: RuleLanguage) -> float:
    locale_key = locale_hint or detected_locale
    return LOCALE_WEIGHT.get(locale_key, LOCALE_WEIGHT[detected_locale]).get(rule_language, 1.0)


def detect_locale(text: str, locale_hint: LocaleHint | None = None) -> str:
    if locale_hint in {"bn", "en", "mixed"}:
        return locale_hint

    bangla_present = BANGLA_SCRIPT.search(text) is not None
    latin_present = LATIN_SCRIPT.search(text) is not None

    if bangla_present and latin_present:
        return "mixed"
    if bangla_present:
        return "bn"

    roman_cues = (
        r"\b(?:vul|bhul|vule|pathaisi|pathayechi|pathalam|taka|ferot|chaise|dise|kete|niyse|niyeche|protarok)\b",
    )
    if any(re.search(pattern, text, re.IGNORECASE) for pattern in roman_cues):
        return "mixed"

    return "en"


def _score_rules(text: str, detected_locale: str) -> dict[CaseType, CaseScore]:
    scores: dict[CaseType, list[int]] = {
        "wrong_transfer": [0, 0],
        "payment_failed": [0, 0],
        "refund_request": [0, 0],
        "phishing_or_social_engineering": [0, 0],
        "other": [0, 0],
    }
    matched_rules: dict[CaseType, int] = {case_type: 0 for case_type in scores}

    for rule in RULES:
        if rule.case_type == "other":
            continue

        best_hit = False
        for match in rule.pattern.finditer(text):
            if rule.negation_sensitive and _is_negated(text, match.start(), match.end()):
                continue
            best_hit = True
            break

        if not best_hit:
            continue

        weight = int(round(rule.weight * _locale_bonus(None, detected_locale, rule.language)))
        current_score = scores[rule.case_type][0] + weight
        scores[rule.case_type][0] = current_score
        matched_rules[rule.case_type] += 1

    result: dict[CaseType, CaseScore] = {}
    for case_type, bucket in scores.items():
        result[case_type] = CaseScore(case_type, bucket[0], matched_rules[case_type])
    result["other"] = CaseScore("other", 0, 0)
    return result


def _severity_for(case_type: CaseType, score: int) -> Severity:
    for threshold, severity in SEVERITY_THRESHOLDS[case_type]:
        if score >= threshold:
            return severity
    return CASE_TO_BASE_SEVERITY[case_type]


def extract_amount(text: str) -> str | None:
    normalized = normalize_text(text)
    match = NUMBER_PATTERN.search(normalized)
    if match is None:
        return None

    number_text = re.sub(r"[\s,]", "", match.group("number"))
    number_text = number_text.translate(str.maketrans("০১২৩৪৫৬৭৮৯", "0123456789"))
    unit = (match.group("unit") or "").lower()

    if unit in {"k", "thousand", "হাজার"}:
        try:
            value = int(number_text) * 1000
        except ValueError:
            return None
        return str(value)

    if number_text.isdigit():
        return str(int(number_text))

    return None


def _primary_amount_phrase(case_type: CaseType, amount: str | None) -> str:
    if amount is None:
        return {
            "wrong_transfer": "money",
            "payment_failed": "a payment",
            "refund_request": "a transaction",
            "phishing_or_social_engineering": "account access",
            "other": "the issue",
        }[case_type]

    return {
        "wrong_transfer": f"{amount} BDT",
        "payment_failed": f"{amount} BDT",
        "refund_request": f"{amount} BDT",
        "phishing_or_social_engineering": f"{amount} BDT",
        "other": f"{amount} BDT",
    }[case_type]


def generate_summary(case_type: CaseType, text: str, amount: str | None) -> str:
    amount_phrase = _primary_amount_phrase(case_type, amount)

    if case_type == "wrong_transfer":
        if amount is None:
            return "Customer reports sending money to the wrong recipient and requests recovery."
        return f"Customer reports sending {amount_phrase} to the wrong recipient and requests recovery."

    if case_type == "payment_failed":
        if amount is None:
            return "Customer reports a failed payment where the transaction did not complete."
        return f"Customer reports a failed payment where {amount_phrase} was deducted but the transaction did not complete."

    if case_type == "refund_request":
        if amount is None:
            return "Customer is requesting a refund for a recent transaction."
        return f"Customer is requesting a refund for {amount_phrase}."

    if case_type == "phishing_or_social_engineering":
        return "Customer reports a suspicious request involving account credentials and requires immediate review."

    return "Customer reports an issue that needs manual triage."


def calculate_confidence(
    top_score: int,
    second_score: int,
    matched_rules: int,
    severity: Severity,
    locale_hint: LocaleHint | None,
    detected_locale: str,
    case_type: CaseType,
) -> float:
    score_component = min(top_score / 24.0, 0.26)
    margin_component = min(max(top_score - second_score, 0) / 18.0, 0.18)
    rule_component = min(matched_rules * 0.045, 0.18)
    severity_component = {"low": 0.00, "medium": 0.04, "high": 0.07, "critical": 0.11}[severity]
    locale_component = 0.04 if locale_hint in {detected_locale, "mixed"} else 0.02 if locale_hint is None else 0.0
    certainty_component = 0.03 if case_type != "other" and top_score > 0 else 0.0

    confidence = 0.50 + score_component + margin_component + rule_component + severity_component + locale_component + certainty_component
    return round(max(MIN_CONFIDENCE, min(MAX_CONFIDENCE, confidence)), 2)


def human_review_required(case_type: CaseType, severity: Severity) -> bool:
    return severity == "critical" or case_type == "phishing_or_social_engineering"


def analyze_ticket(message: str, locale_hint: LocaleHint | None = None) -> TicketAnalysis:
    normalized = normalize_text(message)
    detected_locale = detect_locale(normalized, locale_hint)
    scores = _score_rules(normalized, detected_locale)

    ranked = sorted(
        (scores[case_type] for case_type in scores if case_type != "other"),
        key=lambda item: (item.score, CASE_PRIORITY[item.case_type], item.matched_rules),
        reverse=True,
    )

    top = ranked[0] if ranked and ranked[0].score > 0 else CaseScore("other", 0, 0)
    second = ranked[1] if len(ranked) > 1 else CaseScore("other", 0, 0)

    if top.case_type == "other":
        severity = "low"
    else:
        severity = _severity_for(top.case_type, top.score)

    amount = extract_amount(normalized)
    summary = generate_summary(top.case_type, normalized, amount)
    confidence = calculate_confidence(top.score, second.score, top.matched_rules, severity, locale_hint, detected_locale, top.case_type)

    return TicketAnalysis(
        case_type=top.case_type,
        severity=severity,
        department=CASE_TO_DEPARTMENT[top.case_type],
        agent_summary=summary,
        human_review_required=human_review_required(top.case_type, severity),
        confidence=confidence,
        amount=amount,
        detected_locale=detected_locale,
        top_score=top.score,
        second_score=second.score,
        matched_rules=top.matched_rules,
    )
