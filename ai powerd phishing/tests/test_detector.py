"""
Automated Unit and Integration Test Suite for PhishShield AI.
Tests ML pipeline, URL heuristics, social engineering, headers, and Flask REST endpoints.
"""

import unittest
import json
import os
import sys

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.nlp_analyzer import get_nlp_analyzer
from core.url_analyzer import analyze_url, analyze_all_urls, extract_urls, check_typosquatting
from core.social_engineering import analyze_social_engineering
from core.header_analyzer import analyze_headers
from core.explainability import comprehensive_analysis
from app import app


class TestPhishShield(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.nlp = get_nlp_analyzer()

    # 1. NLP Analyzer Tests
    def test_nlp_phishing_prediction(self):
        phish_text = "URGENT: Your account will be suspended within 2 hours. Verify your credentials immediately at http://login-portal.xyz"
        res = self.nlp.analyze_text(phish_text)
        self.assertEqual(res["prediction"], "PHISHING")
        self.assertGreaterEqual(res["phishing_probability"], 0.6)
        self.assertGreater(len(res["contributing_features"]), 0)

    def test_nlp_ham_prediction(self):
        ham_text = "Hi team, please find the sprint retrospective meeting agenda for tomorrow morning at 10 AM attached. Thanks!"
        res = self.nlp.analyze_text(ham_text)
        self.assertEqual(res["prediction"], "LEGITIMATE")
        self.assertLess(res["phishing_probability"], 0.4)

    # 2. URL Heuristics Tests
    def test_url_ip_detection(self):
        res = analyze_url("http://192.168.1.1/login")
        self.assertTrue(res["is_ip"])
        self.assertGreaterEqual(res["risk_score"], 40)
        self.assertTrue(any(f["type"] == "IP_HOST" for f in res["flags"]))

    def test_url_suspicious_tld(self):
        res = analyze_url("http://update-security-info.xyz")
        self.assertEqual(res["tld"], "xyz")
        self.assertTrue(any(f["type"] == "SUSPICIOUS_TLD" for f in res["flags"]))

    def test_url_typosquatting_subdomain(self):
        res = analyze_url("http://paypal.com.account-verification-portal.net/login")
        self.assertTrue(any(f["type"] == "TYPOSQUATTING" for f in res["flags"]))
        self.assertGreaterEqual(res["risk_score"], 50)

    def test_url_typosquatting_lookalike(self):
        typos = check_typosquatting("paypa1.com")
        self.assertTrue(len(typos) > 0)
        self.assertEqual(typos[0]["brand"], "paypal")

    def test_url_safe(self):
        res = analyze_url("https://www.google.com/search?q=python")
        self.assertEqual(res["verdict"], "SAFE")
        self.assertLess(res["risk_score"], 30)

    # 3. Social Engineering Engine Tests
    def test_social_engineering_triggers(self):
        text = "URGENT: Action required immediately! Your account is suspended due to unauthorized access. Click here to confirm your password within 2 hours."
        res = analyze_social_engineering(text)
        self.assertGreaterEqual(res["vulnerability_score"], 70)
        self.assertIn(res["overall_threat"], ["HIGH", "CRITICAL"])
        self.assertGreater(res["trigger_count"], 3)
        self.assertIn("urgency", res["categories"])
        self.assertIn("fear_coercion", res["categories"])
        self.assertIn("action_forcing", res["categories"])

    # 4. Header Spoofing Tests
    def test_header_display_spoofing(self):
        res = analyze_headers(
            from_header="Microsoft 365 Support <attacker@random-domain.xyz>",
            reply_to_header="phish@evil-box.com"
        )
        self.assertEqual(res["verdict"], "SPOOFED_HIGH_RISK")
        self.assertTrue(any(f["type"] == "DISPLAY_NAME_SPOOFING" for f in res["flags"]))
        self.assertTrue(any(f["type"] == "REPLY_TO_MISMATCH" for f in res["flags"]))

    # 5. Comprehensive Explainability Tests
    def test_comprehensive_phishing(self):
        report = comprehensive_analysis(
            text="URGENT: Your account will be closed. Verify immediately at http://login-microsoft365.xyz/auth",
            subject="Action Required: Account Expiration",
            from_header="Microsoft Account <notice@login-microsoft365.xyz>"
        )
        self.assertEqual(report["overall_verdict"], "CRITICAL_PHISHING")
        self.assertGreaterEqual(report["risk_score"], 70)
        self.assertGreater(len(report["warning_signs"]), 0)
        self.assertGreater(len(report["recommendations"]), 0)
        self.assertIn("<mark", report["highlighted_html"])

    def test_comprehensive_legitimate(self):
        report = comprehensive_analysis(
            text="Hi Sarah, following up on our team discussion yesterday. Here are the meeting notes and project timeline for next sprint.",
            subject="Sprint Sync Notes",
            from_header="Sarah Jenkins <sarah@acmecorp.com>"
        )
        self.assertEqual(report["overall_verdict"], "SAFE")
        self.assertLess(report["risk_score"], 30)

    # 6. Flask API Endpoints
    def test_api_samples(self):
        response = self.app.get('/api/samples')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("samples", data)
        self.assertGreater(len(data["samples"]), 0)

    def test_api_model_stats(self):
        response = self.app.get('/api/model-stats')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("accuracy", data)
        self.assertIn("top_phishing_features", data)

    def test_api_analyze_post(self):
        payload = {
            "text": "Your Netflix membership is on hold. Update billing: http://netflix-billing-center.xyz",
            "subject": "Payment Declined"
        }
        response = self.app.post('/api/analyze', data=json.dumps(payload), content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("overall_verdict", data)
        self.assertIn("risk_score", data)

    def test_api_analyze_url_post(self):
        payload = {"url": "http://paypal.com.phish-site.top/verify"}
        response = self.app.post('/api/analyze-url', data=json.dumps(payload), content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("verdict", data)
        self.assertIn("flags", data)


if __name__ == '__main__':
    unittest.main()
