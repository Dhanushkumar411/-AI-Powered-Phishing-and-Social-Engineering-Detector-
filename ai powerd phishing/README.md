# PhishShield AI — AI-Powered Phishing & Social Engineering Detector

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.8.0-orange.svg)](https://scikit-learn.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1.3-lightgrey.svg)](https://flask.palletsprojects.com/)
[![Tests](https://img.shields.io/badge/Tests-Passing%20(15%2F15)-brightgreen.svg)]()

> **PhishShield AI** is an intelligent cybersecurity threat inspection platform that analyzes suspicious emails, URLs, and message content to detect phishing attempts, uncover deceptive infrastructure, and explain the underlying social engineering manipulation signs with Explainable AI (XAI).

---

## Key Capabilities & Detection Modalities

### 1. NLP & TF-IDF Machine Learning Classifier
- **Word & Character N-Grams:** Extracts unigrams and bigrams (`(1, 2)`) with sublinear term-frequency scaling to capture high-leverage phishing phrases (e.g., `verify account`, `action required`, `wire transfer`, `unauthorized access`).
- **Probabilistic Classification:** Utilizes a calibrated Logistic Regression model with balanced class weighting to output smooth, mathematically calibrated confidence scores (0% to 100%).
- **Explainable AI (XAI) Attribution:** Calculates exact log-odds impact per token ($\text{TF-IDF} \times w_i$), showing the analyst exactly which words and phrases drove the classification toward Phishing or Legitimate.

### 2. Deep URL & Domain Heuristic Analyzer
- **Brand Impersonation & Typosquatting:** Evaluates Levenshtein distance, visual homoglyph substitutions (`0` $\to$ `o`, `1` $\to$ `l`, `vv` $\to$ `w`), and brand compounding (e.g. `apple-security-check.com`) against 50+ major targeted brands.
- **Subdomain Deception:** Detects nested brand prefixes (e.g., `paypal.com.account-update.xyz`).
- **Shannon Domain Entropy:** Measures character randomness to flag algorithmic Domain Generation Algorithms (DGA).
- **High-Risk TLD & IP Hosts:** Detects raw IP hosts (`http://192.168.1.50/login`), non-standard ports (`:8080`, `:2082`), and abusive top-level domains (`.xyz`, `.top`, `.click`, `.buzz`, `.fit`, `.work`, `.ru`, `.tk`).
- **URL Shorteners:** Identifies masking services (`bit.ly`, `tinyurl.com`, `t.co`).

### 3. Social Engineering & Psychological Trigger Taxonomy
Phishing succeeds by manipulating human psychology. PhishShield scans for 6 core social engineering levers:
- **Artificial Urgency & Time Scarcity:** "within 2 hours", "immediate action required", "expires today".
- **Fear & Coercion / Threat:** "account suspended", "legal action", "unauthorized transaction", "police warrant".
- **Authority Pretexting:** Impersonating corporate executives (CEO/CFO), IT helpdesks, HR directors, or government agencies (IRS, FBI).
- **Financial Bait & Greed:** Fake lotteries, unclaimed refunds, crypto giveaways, executive bonuses.
- **Action-Forcing Directives:** "click here", "confirm password", "wire funds", "buy gift cards".
- **Secrecy & Isolation:** Demanding strict secrecy to prevent victims from consulting security teams.

### 4. Email Header & Sender Spoofing Analysis
- **Display Name Deception:** Flags emails where the display name claims a trusted entity (`"PayPal Support"` or `"IT Security"`) but originates from an external or disposable domain.
- **Reply-To Mismatch:** Detects discrepancies between the `From` domain and the `Reply-To` collector domain.
- **Authentication Results:** Parses and evaluates SPF, DKIM, and DMARC failures.

### 5. Interactive Cyber Analyst Workstation UI
- **Animated SVG Threat Gauge:** Dynamic color-shifting meter (Emerald $\to$ Amber $\to$ Crimson).
- **Live In-Text Visual Highlights:** Colors malicious triggers and suspicious links with hover tooltips directly on the analyzed message.
- **Preset Attack Scenarios:** 1-click loading of realistic real-world attacks (Microsoft 365 credential theft, CEO wire fraud, PayPal suspension, DHL customs scam) and clean ham emails.
- **Exportable Incident Reports:** View and print professional Security Incident Reports (PDF/HTML).
- **Model Transparency Modal:** Real-time visibility into cross-validation scores, confusion matrix, vocabulary size, and top feature weights.

---

## Architecture

```
+----------------------------------------------------------------------------+
|                             USER INTERFACE                                 |
|      (Cyberpunk/Dark Slate Workstation, Animated SVG Gauge, Highlights)     |
+----------------------------------------------------------------------------+
                                      |
                           [REST API Endpoints]
                                      |
+----------------------------------------------------------------------------+
|                            APP CONTROLLER                                  |
|            app.py: /api/analyze, /api/analyze-url, /api/model-stats        |
+----------------------------------------------------------------------------+
                                      |
+----------------------------------------------------------------------------+
|                        EXPLAINABILITY & AGGREGATION                        |
|   Weighted Composite Scoring, Severity Rules, Warning Signs, Recommendations |
+------------------+-------------------+--------------------+----------------+
                   |                   |                    |
        +----------v---------+ +-------v--------+  +--------v-------+
        |   NLP & TF-IDF     | | URL HEURISTICS |  | SOCIAL ENG.    |
        |   ML Pipeline      | | Typosquatting  |  | Psychological  |
        |   (Scikit-Learn)   | | Shannon Entropy|  | Trigger Engine |
        +--------------------+ +----------------+  +----------------+
```

---

## Directory Structure

```
d:\ai powerd phishing\
├── app.py                     # Flask application entry point and REST APIs
├── requirements.txt           # Project dependencies
├── README.md                  # System documentation & usage guide
├── core/
│   ├── __init__.py            # Core package initializer
│   ├── nlp_analyzer.py        # TF-IDF inference & feature contribution extraction
│   ├── url_analyzer.py        # URL lexical heuristics, entropy, typosquatting
│   ├── social_engineering.py  # Psychological trigger analyzer & scoring
│   ├── header_analyzer.py     # Email sender spoofing & header verification
│   └── explainability.py      # Composite scoring, highlights, & recommendations
├── model/
│   ├── dataset.py             # Curated & synthetic diverse training corpus
│   ├── train.py               # ML training script, evaluation & serialization
│   ├── phishing_model.joblib  # Serialized trained TF-IDF + LogisticRegression model
│   └── metrics.json           # Model evaluation metrics & vocabulary weights
├── static/
│   ├── css/
│   │   └── style.css          # Cyber security dark workstation theme styles
│   └── js/
│       └── app.js             # Client interactivity, animated gauge, API calls
├── templates/
│   ├── index.html             # Main analysis workstation dashboard
│   └── report.html            # Printable / Exportable Incident Report
└── tests/
    └── test_detector.py       # 15 unit and integration tests (100% pass)
```

---

## Quick Start & Installation

### 1. Prerequisites
- Python 3.10+ installed
- Git (optional)

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Launch the Web Application
```bash
python app.py --port 5000
```
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## Testing & Verification

The project includes an automated test suite covering all modules:
```bash
python tests/test_detector.py
```
Expected output:
```
...............
----------------------------------------------------------------------
Ran 15 tests in 4.5s

OK
```

---

## Re-training the ML Model

To re-train the TF-IDF pipeline and generate fresh evaluation metrics:
```bash
python model/train.py
```
The script outputs:
- **5-Fold Cross Validation F1 Score:** `~99.8%`
- **Test Set Accuracy & F1:** `1.000`
- Confusion matrix and top 30 phishing vs legitimate n-grams saved to `model/metrics.json`.

---

## REST API Documentation

### 1. Comprehensive Threat Analysis
- **Endpoint:** `POST /api/analyze`
- **Payload:**
```json
{
  "text": "Your account will be closed in 2 hours. Verify at http://login-portal.xyz",
  "subject": "URGENT Account Update",
  "from_header": "IT Security <helpdesk@login-portal.xyz>",
  "reply_to": "collector@attacker.com"
}
```
- **Response:**
```json
{
  "overall_verdict": "CRITICAL_PHISHING",
  "verdict_badge": "Malicious Phishing Attack",
  "risk_score": 75.0,
  "scores_breakdown": {
    "ml_nlp_score": 82.0,
    "url_threat_score": 65.0,
    "social_engineering_score": 70.0,
    "header_spoof_score": 80.0
  },
  "warning_signs": [...],
  "recommendations": [...],
  "highlighted_html": "..."
}
```

### 2. URL Deep Scan
- **Endpoint:** `POST /api/analyze-url`
- **Payload:** `{"url": "http://paypal.com.verify-billing.xyz/login"}`
- **Response:** Lexical flags, entropy, typosquatting brand matches, protocol security.

### 3. Presets & Model Statistics
- `GET /api/samples`: Returns curated preset test cases.
- `GET /api/model-stats`: Returns model metrics, accuracy, and feature weights.

---

## License
MIT License. Created for defensive cybersecurity analysis and education.
