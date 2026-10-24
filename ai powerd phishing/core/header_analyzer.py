"""
Email Header & Sender Spoofing Analyzer.
Detects display name deception, sender/Reply-To divergence,
free webmail corporate impersonation, and authentication failures (SPF/DKIM/DMARC).
"""

import re
from email.utils import parseaddr

# Common free webmail providers (suspicious when claiming corporate identity)
FREE_WEBMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "protonmail.com", "proton.me", "mail.com", "zoho.com", "yandex.com",
    "gmx.com", "icloud.com", "fastmail.com", "tutanota.com"
}

# Major entities and brands whose names are frequently impersonated in display names
KNOWN_ENTITIES = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "office365.com", "live.com"],
    "office 365": ["microsoft.com", "office365.com"],
    "google": ["google.com", "googlemail.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com"],
    "wells fargo": ["wellsfargo.com"],
    "bank of america": ["bankofamerica.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "usps": ["usps.com"],
    "ups": ["ups.com"],
    "irs": ["irs.gov"],
    "it support": [],
    "help desk": [],
    "security team": [],
    "admin": [],
    "payroll": [],
    "ceo": []
}

SUSPICIOUS_SENDER_TLDS = {
    "xyz", "top", "click", "buzz", "fit", "work", "gq", "cf", "ml", "tk",
    "ru", "cc", "download", "stream", "racing", "loan", "club"
}


def parse_raw_headers(raw_header_text):
    """Parses raw email header text into a normalized key-value dictionary."""
    headers = {}
    if not raw_header_text:
        return headers

    lines = raw_header_text.strip().splitlines()
    current_key = None
    current_val = []

    for line in lines:
        if line.startswith((' ', '\t')) and current_key:
            # Continuation of previous header line
            current_val.append(line.strip())
        else:
            if current_key:
                headers[current_key.lower()] = " ".join(current_val)
            if ':' in line:
                key, val = line.split(':', 1)
                current_key = key.strip()
                current_val = [val.strip()]
            else:
                current_key = None

    if current_key:
        headers[current_key.lower()] = " ".join(current_val)

    return headers


def analyze_headers(from_header=None, reply_to_header=None, raw_headers=None):
    """
    Analyzes email sender information and headers for spoofing and impersonation indicators.
    """
    parsed_headers = {}
    if raw_headers:
        parsed_headers = parse_raw_headers(raw_headers)

    from_field = from_header or parsed_headers.get("from", "")
    reply_to_field = reply_to_header or parsed_headers.get("reply-to", "")
    auth_results = parsed_headers.get("authentication-results", "") + " " + parsed_headers.get("received-spf", "")

    flags = []
    risk_score = 0

    # Parse From field: e.g. "PayPal Security" <support@fake-domain.xyz>
    display_name, sender_email = parseaddr(from_field)
    sender_domain = sender_email.split('@')[-1].lower() if '@' in sender_email else ""

    # Parse Reply-To field
    reply_display, reply_email = parseaddr(reply_to_field)
    reply_domain = reply_email.split('@')[-1].lower() if '@' in reply_email else ""

    # 1. Display Name Impersonation
    display_lower = display_name.lower()
    for entity, valid_domains in KNOWN_ENTITIES.items():
        if entity in display_lower and sender_domain:
            # Check if actual domain is an authorized legitimate domain
            is_valid = any(sender_domain == d or sender_domain.endswith('.' + d) for d in valid_domains)
            if valid_domains and not is_valid:
                risk_score += 45
                flags.append({
                    "type": "DISPLAY_NAME_SPOOFING",
                    "title": f"Display Name Spoofing ({entity.upper()})",
                    "severity": "CRITICAL",
                    "description": f"The sender claims to be '{display_name}', but the email originates from an unrelated domain: '{sender_domain}'."
                })
                break
            elif not valid_domains:
                # Internal role impersonation (e.g., IT Support, CEO, Admin)
                if sender_domain in FREE_WEBMAIL_PROVIDERS or any(sender_domain.endswith('.' + tld) for tld in SUSPICIOUS_SENDER_TLDS):
                    risk_score += 35
                    flags.append({
                        "type": "ROLE_IMPERSONATION",
                        "title": f"Internal Role Impersonation ('{display_name}')",
                        "severity": "HIGH",
                        "description": f"Sender claims internal authority '{display_name}' using an untrusted or public external domain: '{sender_domain}'."
                    })
                    break

    # 2. Reply-To Mismatch
    if sender_domain and reply_domain and sender_domain != reply_domain:
        risk_score += 30
        flags.append({
            "type": "REPLY_TO_MISMATCH",
            "title": "Sender and Reply-To Domain Discrepancy",
            "severity": "HIGH",
            "description": f"Email is sent from '{sender_domain}', but replies are directed to a different destination: '{reply_domain}'."
        })

    # 3. Suspicious Sender TLD
    sender_tld = sender_domain.split('.')[-1] if '.' in sender_domain else ""
    if sender_tld in SUSPICIOUS_SENDER_TLDS:
        risk_score += 25
        flags.append({
            "type": "SUSPICIOUS_SENDER_TLD",
            "title": f"Suspicious Sender TLD (.{sender_tld})",
            "severity": "MEDIUM",
            "description": f"Sender domain uses a top-level domain (.{sender_tld}) heavily correlated with malicious disposable infrastructure."
        })

    # 4. Authentication Failures (SPF / DKIM / DMARC)
    if auth_results:
        auth_lower = auth_results.lower()
        if "spf=fail" in auth_lower or "spf=softfail" in auth_lower:
            risk_score += 30
            flags.append({
                "type": "SPF_FAIL",
                "title": "SPF Authentication Failure",
                "severity": "HIGH",
                "description": "Sender Policy Framework (SPF) failed. The sending mail server is not authorized to send on behalf of this domain."
            })
        if "dkim=fail" in auth_lower:
            risk_score += 25
            flags.append({
                "type": "DKIM_FAIL",
                "title": "DKIM Signature Invalid",
                "severity": "MEDIUM",
                "description": "DomainKeys Identified Mail (DKIM) cryptographic signature verification failed or was tampered with."
            })
        if "dmarc=fail" in auth_lower:
            risk_score += 35
            flags.append({
                "type": "DMARC_FAIL",
                "title": "DMARC Verification Failed",
                "severity": "CRITICAL",
                "description": "Domain-based Message Authentication (DMARC) alignment check failed."
            })

    final_score = min(max(risk_score, 0), 100)
    verdict = "LEGITIMATE" if final_score < 25 else ("SUSPICIOUS" if final_score < 60 else "SPOOFED_HIGH_RISK")

    return {
        "from_name": display_name,
        "from_address": sender_email,
        "from_domain": sender_domain,
        "reply_to_address": reply_email,
        "reply_to_domain": reply_domain,
        "risk_score": final_score,
        "verdict": verdict,
        "flags": flags
    }


if __name__ == "__main__":
    sample_raw = """From: "PayPal Account Security" <service-alert@update-notice.xyz>
Reply-To: phisher-collector@temporary-inbox.com
Subject: Suspicious transaction detected
Authentication-Results: spf=fail (sender IP is 198.51.100.1)
"""
    res = analyze_headers(raw_headers=sample_raw)
    print(f"Header Verdict: {res['verdict']} ({res['risk_score']}%)")
    for f in res["flags"]:
        print(f" - [{f['severity']}] {f['title']}: {f['description']}")
