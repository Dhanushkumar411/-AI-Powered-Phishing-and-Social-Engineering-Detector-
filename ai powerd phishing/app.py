"""
Flask Web Application for AI-Powered Phishing and Social Engineering Detector.
Serves interactive cyber dashboard, REST APIs for text/URL analysis,
sample attacks, and model evaluation metrics.
"""

import os
import json
from flask import Flask, render_template, request, jsonify

from core.explainability import comprehensive_analysis
from core.url_analyzer import analyze_url

app = Flask(__name__)
app.config['SECRET_KEY'] = 'phish-shield-secret-token-2026'

METRICS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model", "metrics.json")

# Predefined realistic sample cases for 1-click testing in the UI
PRESET_SAMPLES = [
    {
        "id": "m365_credential_theft",
        "title": "Microsoft 365 Password Expiration",
        "category": "Credential Theft",
        "risk_tier": "High Risk",
        "from_header": "Microsoft Security Team <support@m365-security-portal.xyz>",
        "reply_to": "admin@attacker-inbox.com",
        "subject": "ACTION REQUIRED: Your Microsoft 365 Password Expires in 2 Hours",
        "body": "Dear Employee,\n\nYour Microsoft 365 corporate account password will expire today within 2 hours. To avoid disruption to your Outlook email, SharePoint access, and Teams messaging, you must authenticate your current credentials immediately.\n\nPlease verify your login credentials here: http://login-microsoft365-security-portal.xyz/verify-login\n\nFailure to complete this verification will result in immediate mailbox suspension.\n\nBest regards,\nIT Global Security Operations"
    },
    {
        "id": "ceo_bec_wire",
        "title": "CEO Urgent Wire Transfer (BEC)",
        "category": "Business Email Compromise",
        "risk_tier": "High Risk",
        "from_header": "David Sterling, CEO <david.sterling.corporate@gmail.com>",
        "reply_to": "david.sterling.exec@gmail.com",
        "subject": "Confidential Request - Process Wire Transfer Today",
        "body": "Hi, are you at your desk right now?\n\nI am currently tied up in an offsite executive board meeting with our acquisition partners and cannot take phone calls. We have an urgent invoice of $48,500 that must be settled with a new strategic vendor before 4:00 PM today to close the transaction.\n\nPlease reply immediately so I can send the wiring instructions and account details. Keep this strictly confidential between us.\n\nThanks,\nDavid Sterling\nChief Executive Officer"
    },
    {
        "id": "paypal_unauthorized_charge",
        "title": "PayPal Account Restriction Notice",
        "category": "Financial Phish",
        "risk_tier": "High Risk",
        "from_header": "PayPal Fraud Protection <service@notification-center.click>",
        "reply_to": "",
        "subject": "Security Alert: Unusual activity detected on your PayPal account",
        "body": "Dear Valued Customer,\n\nWe detected an unauthorized transaction of $849.99 to Best Buy on your PayPal account from an IP address in Moscow, Russia. For your protection, your debit card and account capabilities have been temporarily restricted.\n\nIf you did not authorize this payment, dispute it immediately by clicking the link below to verify your identity and restore your account:\nhttp://paypal.com.verification-center-security.net/dispute?id=94812\n\nThank you for choosing PayPal."
    },
    {
        "id": "dhl_parcel_delivery",
        "title": "DHL Parcel Customs Fee Scam",
        "category": "Delivery Scam",
        "risk_tier": "High Risk",
        "from_header": "DHL Express Tracking <tracking-update@dhl-express-redelivery-notice.xyz>",
        "reply_to": "",
        "subject": "Package Delivery Pending: Customs clearance fee required",
        "body": "Your DHL Express parcel #DHL-9281903 has arrived at the destination distribution facility, but delivery is on hold. A customs clearance fee of $2.49 is pending payment.\n\nTo schedule immediate redelivery to your address, confirm your delivery information and pay the clearance charge: http://dhl-express-redelivery-notice.xyz/track\n\nIf unpaid within 24 hours, the package will be returned to the sender."
    },
    {
        "id": "geek_squad_fake_invoice",
        "title": "Geek Squad Auto-Renewal Scam",
        "category": "Fake Invoice",
        "risk_tier": "High Risk",
        "from_header": "Best Buy Geek Squad <billing-support@tech-support-renewal.buzz>",
        "reply_to": "",
        "subject": "Invoice #GS-88391: Auto-Renewal for Total Tech Support",
        "body": "Thank you for continuing your subscription with Geek Squad! Your 3-year Total Tech Support package has auto-renewed for $499.99 and has been debited from your checking account.\n\nIf you did not place or authorize this renewal, call our cancellation department immediately at +1-888-555-0199 or cancel online here: http://geeksquad-refund-cancellation.work/dispute\n\nRequests must be made within 24 hours of receiving this invoice."
    },
    {
        "id": "github_pr_legitimate",
        "title": "GitHub Pull Request Review (Ham)",
        "category": "Legitimate Ham",
        "risk_tier": "Safe",
        "from_header": "GitHub Notifications <notifications@github.com>",
        "reply_to": "reply+AB7612@reply.github.com",
        "subject": "[company/api-gateway] Pull Request #482: Implement rate limiting middleware",
        "body": "Hey team,\n\nI have finished implementing the Redis-backed token bucket rate limiter for the public API endpoints. Unit tests and load testing with 10,000 req/sec passed successfully on GitHub Actions.\n\nPlease review the code changes when you have a moment:\nhttps://github.com/company/api-gateway/pull/482\n\nFeedback and code comments are welcome. Thanks!\n- Alex Chen"
    },
    {
        "id": "amazon_legitimate_order",
        "title": "Amazon Order Confirmation (Ham)",
        "category": "Legitimate Ham",
        "risk_tier": "Safe",
        "from_header": "Amazon.com <auto-confirm@amazon.com>",
        "reply_to": "",
        "subject": "Your Amazon.com order #112-8823190-4491023 has shipped!",
        "body": "Hello,\n\nGreat news! Your package is on its way. It was shipped via USPS and is estimated to arrive tomorrow by 8:00 PM.\n\nItem ordered:\n'Designing Data-Intensive Applications' by Martin Kleppmann\n\nYou can track your shipment anytime or manage your delivery preferences at: https://www.amazon.com/your-orders\n\nThank you for shopping with us!"
    },
    {
        "id": "team_meeting_legitimate",
        "title": "Sprint Planning & Retrospective (Ham)",
        "category": "Legitimate Ham",
        "risk_tier": "Safe",
        "from_header": "Sarah Jenkins <sarah.jenkins@acmecorp.com>",
        "reply_to": "",
        "subject": "Sprint 24 Retrospective Agenda & Demo Notes",
        "body": "Hi everyone,\n\nHere is the outline for tomorrow morning's sprint demo and retro at 10:00 AM in Conference Room B and on Google Meet.\n\nAgenda:\n1. Sprint 24 achievements & demo of analytics widget\n2. Jira burn-down chart review\n3. What went well & areas for improvement\n4. Preliminary backlog estimation for Sprint 25\n\nPlease add any talking points to our shared Google Doc before 9:30 AM.\n\nSee you tomorrow,\nSarah"
    }
]


@app.route("/")
def index():
    """Renders the main Cyber Defense analysis workstation dashboard."""
    return render_template("index.html")


@app.route("/report")
def report_view():
    """Renders printable incident report page."""
    return render_template("report.html")


@app.route("/api/analyze", methods=["POST"])
def analyze_endpoint():
    """
    Main analysis endpoint. Analyzes email text, subject, headers, and extracted URLs.
    """
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    subject = data.get("subject", "")
    from_header = data.get("from_header", "")
    reply_to = data.get("reply_to", "")
    raw_headers = data.get("raw_headers", "")

    if not text.strip() and not subject.strip() and not raw_headers.strip():
        return jsonify({
            "error": "Please provide email content, subject, or raw headers to analyze."
        }), 400

    report = comprehensive_analysis(
        text=text,
        subject=subject,
        from_header=from_header,
        reply_to_header=reply_to,
        raw_headers=raw_headers
    )

    return jsonify(report)


@app.route("/api/analyze-url", methods=["POST"])
def analyze_url_endpoint():
    """Dedicated endpoint to analyze a single URL."""
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL provided."}), 400

    if not url.startswith(('http://', 'https://', 'ftp://')):
        url = 'http://' + url

    result = analyze_url(url)
    return jsonify(result)


@app.route("/api/samples", methods=["GET"])
def get_samples():
    """Returns curated preset samples for instant UI testing."""
    return jsonify({
        "total": len(PRESET_SAMPLES),
        "samples": PRESET_SAMPLES
    })


@app.route("/api/model-stats", methods=["GET"])
def get_model_stats():
    """Returns trained model metrics, vocabulary stats, and feature coefficients."""
    if os.path.exists(METRICS_PATH):
        try:
            with open(METRICS_PATH, "r", encoding="utf-8") as f:
                metrics = json.load(f)
            return jsonify(metrics)
        except Exception as e:
            return jsonify({"error": f"Failed to load metrics: {str(e)}"}), 500
    return jsonify({"error": "Metrics file not found. Please train model first."}), 404


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Resource not found"}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error occurred"}), 500


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="PhishShield AI Web Server")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", 5000)), help="Port to run server on")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host IP to bind")
    args = parser.parse_args()

    print(f"Starting PhishShield AI Server on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False)
