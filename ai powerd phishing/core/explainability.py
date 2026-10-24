"""
Explainability & Decision Aggregation Engine.
Combines Machine Learning inference, URL heuristics, psychological triggers,
and header spoofing into a unified risk score, structured warning signs,
remediation guidance, and interactive text highlighting.
"""

import html
import os
import sys
import re

# Ensure workspace root is in python path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

try:
    from core.nlp_analyzer import get_nlp_analyzer
    from core.url_analyzer import analyze_all_urls
    from core.social_engineering import analyze_social_engineering
    from core.header_analyzer import analyze_headers
except ImportError:
    from nlp_analyzer import get_nlp_analyzer
    from url_analyzer import analyze_all_urls
    from social_engineering import analyze_social_engineering
    from header_analyzer import analyze_headers


def generate_highlighted_html(text, triggers, urls):
    """
    Renders text with embedded HTML span/mark tags for visual inspection in the UI.
    Highlights psychological triggers and detected URLs with tooltips.
    """
    if not text:
        return ""

    escaped_text = html.escape(text)

    # Replace URLs with custom pill markers
    for u in urls:
        raw_url = u["url"]
        escaped_url = html.escape(raw_url)
        risk_class = "url-malicious" if u["risk_score"] >= 65 else ("url-suspicious" if u["risk_score"] >= 30 else "url-safe")
        tooltip = f"URL Risk: {u['risk_score']}% ({u['verdict']})"
        replacement = f'<span class="highlight-url {risk_class}" data-tooltip="{tooltip}">{escaped_url}</span>'
        escaped_text = escaped_text.replace(escaped_url, replacement)

    # Highlight psychological triggers
    for trig in triggers:
        raw_phrase = trig["phrase"]
        escaped_phrase = html.escape(raw_phrase)
        cat_class = f"trigger-{trig['category']}"
        tooltip = f"{trig['category_title']}: '{escaped_phrase}'"
        # Only replace if not already part of an HTML tag
        pattern = re.compile(re.escape(escaped_phrase), re.IGNORECASE)
        replacement = f'<mark class="highlight-trigger {cat_class}" data-tooltip="{tooltip}">{escaped_phrase}</mark>'
        escaped_text = pattern.sub(replacement, escaped_text, count=1)

    return escaped_text


def generate_warning_signs(nlp_res, url_res, se_res, header_res):
    """Compiles human-readable warning signs and red flags."""
    warnings = []

    # 1. Header Spoofing Warnings
    for flag in header_res.get("flags", []):
        warnings.append({
            "category": "Sender Identity",
            "title": flag["title"],
            "severity": flag["severity"],
            "description": flag["description"]
        })

    # 2. URL and Link Warnings
    for u in url_res.get("results", []):
        for flag in u.get("flags", []):
            warnings.append({
                "category": "Embedded Links",
                "title": f"{flag['name']} in {u['hostname']}",
                "severity": flag["severity"],
                "description": flag["description"]
            })

    # 3. Psychological / Social Engineering Warnings
    for cat_id, cat_data in se_res.get("categories", {}).items():
        if cat_data["match_count"] > 0:
            severity = "HIGH" if cat_data["score"] >= 70 else "MEDIUM"
            matched_str = ", ".join([f"'{m}'" for m in cat_data["matches"][:3]])
            warnings.append({
                "category": "Social Engineering",
                "title": cat_data["title"],
                "severity": severity,
                "description": f"{cat_data['description']} Detected triggers: {matched_str}."
            })

    # 4. Machine Learning Semantic Findings
    if nlp_res.get("prediction") == "PHISHING":
        top_phish_terms = [f"'{f['term']}'" for f in nlp_res.get("contributing_features", []) if f["direction"] == "phishing"][:4]
        if top_phish_terms:
            warnings.append({
                "category": "NLP Linguistic Analysis",
                "title": f"Phishing Language Patterns Detected (ML Confidence {nlp_res['phishing_probability']*100:.1f}%)",
                "severity": "HIGH",
                "description": f"The statistical model identified strong semantic similarity with credential theft campaigns, driven by terms: {', '.join(top_phish_terms)}."
            })

    return warnings


def generate_recommendations(overall_verdict, warnings):
    """Provides actionable, prioritized defensive recommendations based on findings."""
    recommendations = []

    if overall_verdict == "SAFE":
        recommendations.append("The message displays normal communication patterns. Standard security precautions still apply.")
        recommendations.append("Always verify unexpected links or requests before submitting passwords or personal details.")
        return recommendations

    # High / Suspicious recommendations
    recommendations.append("DO NOT click on any embedded links or download attachments from this message.")
    recommendations.append("DO NOT reply or provide sensitive information, passwords, MFA codes, or credit card numbers.")

    has_url_issue = any(w["category"] == "Embedded Links" for w in warnings)
    if has_url_issue:
        recommendations.append("If you need to check this service, navigate to the official website directly by typing its known address into your browser.")

    has_spoofing = any(w["category"] == "Sender Identity" for w in warnings)
    if has_spoofing:
        recommendations.append("The sender address or display name appears spoofed. Verify the sender's identity using an alternative, verified communication channel (phone, internal chat).")

    has_urgency = any("Urgency" in w.get("title", "") for w in warnings)
    if has_urgency:
        recommendations.append("Beware of artificial urgency. Attackers create false deadlines (e.g., 'within 2 hours') to trigger rushed decisions.")

    recommendations.append("Report this message immediately to your organization's IT Security / SOC team or email abuse desk.")
    return recommendations


def comprehensive_analysis(text, subject="", from_header="", reply_to_header="", raw_headers=""):
    """
    Performs full multi-modal security analysis across text, URLs, headers, and social engineering.
    Returns complete aggregated report.
    """
    combined_text = (subject + "\n" + text).strip() if subject else text.strip()

    # 1. NLP Machine Learning Analysis
    nlp_analyzer = get_nlp_analyzer()
    nlp_res = nlp_analyzer.analyze_text(combined_text)

    # 2. URL & Domain Heuristics
    url_res = analyze_all_urls(combined_text)

    # 3. Social Engineering & Psychological Triggers
    se_res = analyze_social_engineering(combined_text)

    # 4. Email Header & Sender Spoofing
    header_res = analyze_headers(from_header, reply_to_header, raw_headers)

    # 5. Composite Risk Score Calculation
    ml_score = nlp_res["phishing_probability"] * 100.0
    url_score = url_res["max_risk_score"]
    se_score = se_res["vulnerability_score"]
    header_score = header_res["risk_score"]

    # Weighted baseline: NLP (35%) + URLs (30%) + Social Engineering (20%) + Headers (15%)
    weighted_score = (
        (ml_score * 0.35) +
        (url_score * 0.30) +
        (se_score * 0.20) +
        (header_score * 0.15)
    )

    # Escalation Rules:
    # If a critical URL typosquat/IP exists, or critical display spoofing exists, elevate minimum score
    if url_score >= 80:
        weighted_score = max(weighted_score, 85.0)
    elif url_score >= 60:
        weighted_score = max(weighted_score, 65.0)

    if header_score >= 80:
        weighted_score = max(weighted_score, 80.0)

    if se_score >= 85 and ml_score >= 60:
        weighted_score = max(weighted_score, 85.0)

    final_risk_score = min(max(round(weighted_score, 1), 0.0), 100.0)

    # Final Overall Verdict
    if final_risk_score < 30.0:
        overall_verdict = "SAFE"
        verdict_badge = "Legitimate / Low Risk"
        verdict_class = "verdict-safe"
    elif final_risk_score < 65.0:
        overall_verdict = "SUSPICIOUS"
        verdict_badge = "Suspicious / Potential Threat"
        verdict_class = "verdict-suspicious"
    else:
        overall_verdict = "CRITICAL_PHISHING"
        verdict_badge = "Malicious Phishing Attack"
        verdict_class = "verdict-critical"

    # Warning Signs & Explanations
    warning_signs = generate_warning_signs(nlp_res, url_res, se_res, header_res)
    recommendations = generate_recommendations(overall_verdict, warning_signs)
    highlighted_html = generate_highlighted_html(combined_text, se_res["matched_triggers"], url_res["results"])

    return {
        "overall_verdict": overall_verdict,
        "verdict_badge": verdict_badge,
        "verdict_class": verdict_class,
        "risk_score": final_risk_score,
        "input_summary": {
            "subject": subject,
            "has_headers": bool(from_header or reply_to_header or raw_headers),
            "char_count": len(combined_text),
            "urls_count": url_res["urls_detected"]
        },
        "scores_breakdown": {
            "ml_nlp_score": round(ml_score, 1),
            "url_threat_score": round(url_score, 1),
            "social_engineering_score": round(se_score, 1),
            "header_spoof_score": round(header_score, 1)
        },
        "nlp_analysis": nlp_res,
        "url_analysis": url_res,
        "social_engineering": se_res,
        "header_analysis": header_res,
        "warning_signs": warning_signs,
        "recommendations": recommendations,
        "highlighted_html": highlighted_html
    }


if __name__ == "__main__":
    sample_text = "URGENT: Microsoft 365 password will expire in 2 hours. Go to http://microsoft-portal-login.xyz/auth immediately to verify."
    report = comprehensive_analysis(
        text=sample_text,
        subject="Action Required: Microsoft 365 Account Alert",
        from_header="Microsoft Security <admin@microsoft-portal-login.xyz>"
    )
    print(f"Overall Verdict: {report['verdict_badge']} (Risk: {report['risk_score']}%)")
    print(f"Warnings: {len(report['warning_signs'])}")
    for w in report["warning_signs"]:
        print(f" - [{w['severity']}] {w['title']}")
