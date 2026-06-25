from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from app.classifier import analyze_ticket, extract_amount, normalize_text
from app.main import app


class ClassifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)

    def test_health_endpoint(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["service"], "QueueStorm Warmup API")
        self.assertEqual(payload["version"], "1.0.0")
        self.assertEqual(payload["environment"], "development")
        self.assertTrue(payload["timestamp"])
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertEqual(response.headers["x-frame-options"], "DENY")
        self.assertEqual(response.headers["referrer-policy"], "no-referrer")
        self.assertIn("no-store", response.headers["cache-control"])

    def test_error_envelope_for_blank_ticket_id(self) -> None:
        response = self.client.post(
            "/sort-ticket",
            json={"ticket_id": "   ", "message": "I sent money to the wrong number."},
        )
        self.assertEqual(response.status_code, 422)
        payload = response.json()
        self.assertTrue(payload["error"])
        self.assertEqual(payload["status_code"], 422)
        self.assertEqual(payload["message"], "Validation failed.")

    def test_english_examples(self) -> None:
        self.assertEqual(analyze_ticket("I sent money to wrong number").case_type, "wrong_transfer")
        self.assertEqual(analyze_ticket("I accidentally transferred money").case_type, "wrong_transfer")
        self.assertEqual(analyze_ticket("Payment failed but money deducted").case_type, "payment_failed")
        self.assertEqual(analyze_ticket("Please refund my transaction").case_type, "refund_request")
        self.assertEqual(analyze_ticket("Someone asked my OTP").case_type, "phishing_or_social_engineering")
        self.assertEqual(analyze_ticket("App crashes on startup").case_type, "other")

    def test_pure_bangla_examples(self) -> None:
        self.assertEqual(analyze_ticket("আমি ভুল নাম্বারে টাকা পাঠিয়েছি।").case_type, "wrong_transfer")
        self.assertEqual(analyze_ticket("লেনদেন ব্যর্থ হয়েছে কিন্তু টাকা কেটে নিয়েছে।").case_type, "payment_failed")
        self.assertEqual(analyze_ticket("আমি রিফান্ড চাই।").case_type, "refund_request")
        self.assertEqual(analyze_ticket("আমাকে ওটিপি দিতে বলেছে।").case_type, "phishing_or_social_engineering")

    def test_roman_bangla_examples(self) -> None:
        self.assertEqual(analyze_ticket("ami vul number e taka pathaisi").case_type, "wrong_transfer")
        self.assertEqual(analyze_ticket("ami vule taka pathaisi").case_type, "wrong_transfer")
        self.assertEqual(analyze_ticket("taka kete niyse").case_type, "payment_failed")
        self.assertEqual(analyze_ticket("otp chaise").case_type, "phishing_or_social_engineering")
        self.assertEqual(analyze_ticket("refund chai").case_type, "refund_request")

    def test_locale_hints(self) -> None:
        self.assertEqual(analyze_ticket("ভুল নাম্বারে টাকা পাঠিয়েছি", "bn").case_type, "wrong_transfer")
        self.assertEqual(analyze_ticket("I sent money to wrong number", "en").case_type, "wrong_transfer")
        self.assertEqual(analyze_ticket("ami vul account e taka pathaisi", "mixed").case_type, "wrong_transfer")

    def test_negation_detection(self) -> None:
        self.assertNotEqual(analyze_ticket("I did not share my OTP").case_type, "phishing_or_social_engineering")
        self.assertNotEqual(analyze_ticket("আমি ওটিপি দিইনি").case_type, "phishing_or_social_engineering")

    def test_multiple_intents_priority(self) -> None:
        analysis = analyze_ticket("Payment failed and now I want a refund")
        self.assertEqual(analysis.case_type, "payment_failed")
        self.assertEqual(analysis.severity, "high")

        analysis = analyze_ticket("Wrong transfer and someone asked for my OTP")
        self.assertEqual(analysis.case_type, "phishing_or_social_engineering")
        self.assertTrue(analysis.human_review_required)

    def test_amount_extraction(self) -> None:
        self.assertEqual(extract_amount("sent 5,000 BDT"), "5000")
        self.assertEqual(extract_amount("sent 5k"), "5000")
        self.assertEqual(extract_amount("sent 5 thousand taka"), "5000")
        self.assertEqual(extract_amount("sent ৫০০০"), "5000")
        self.assertEqual(extract_amount("sent ৫ হাজার"), "5000")

    def test_summary_includes_amount(self) -> None:
        analysis = analyze_ticket("I sent 5000 taka to the wrong number")
        self.assertIn("5000 BDT", analysis.agent_summary)
        self.assertNotIn("OTP", analysis.agent_summary)
        self.assertNotIn("PIN", analysis.agent_summary)

    def test_unknown_issue(self) -> None:
        analysis = analyze_ticket("The app freezes on launch")
        self.assertEqual(analysis.case_type, "other")
        self.assertEqual(analysis.severity, "low")
        self.assertFalse(analysis.human_review_required)

    def test_api_round_trip(self) -> None:
        response = self.client.post(
            "/sort-ticket",
            json={
                "ticket_id": "T-001",
                "channel": "app",
                "locale": "en",
                "message": "I sent 5000 taka to a wrong number this morning, please help me get it back",
            },
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["case_type"], "wrong_transfer")
        self.assertEqual(payload["severity"], "high")
        self.assertEqual(payload["department"], "dispute_resolution")
        self.assertIn("5000 BDT", payload["agent_summary"])


if __name__ == "__main__":
    unittest.main()
