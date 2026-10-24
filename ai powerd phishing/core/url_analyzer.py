"""
Deep URL and Domain Heuristics Analyzer.
Detects typosquatting, suspicious TLDs, IP hosts, domain entropy (DGA),
subdomain deception, URL shorteners, and brand impersonation.
"""

import re
import math
from urllib.parse import urlparse

# High-risk / frequently abused top-level domains in phishing campaigns
SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "buzz", "fit", "work", "gq", "cf", "ml", "tk",
    "ru", "cc", "to", "rest", "country", "stream", "download", "racing",
    "loan", "win", "club", "date", "faith", "review", "trade", "accountant",
    "science", "party", "kim", "cricket", "men", "bid", "link", "info"
}

# Known URL shorteners that mask the true destination
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st", "tiny.cc", "bc.vc"
}

# High-profile brands frequently targeted by phishing campaigns
TARGETED_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix",
    "chase", "wellsfargo", "bankofamerica", "citibank", "capitalone",
    "instagram", "facebook", "linkedin", "twitter", "dropbox",
    "docusign", "adobe", "binance", "coinbase", "dhl", "fedex", "usps", "ups"
]

# Sensitive path/query keywords commonly used in phishing landing pages
SENSITIVE_KEYWORDS = {
    "login", "signin", "verify", "verification", "update", "wallet",
    "secure", "account", "banking", "password", "confirm", "confirmation",
    "authenticate", "recovery", "reactivate", "suspend", "unlock", "portal",
    "credential", "billing", "invoice", "dispute", "claim"
}

# Common character substitution lookalikes (homoglyphs/leetspeak)
HOMOGLYPH_MAP = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
    '7': 't', '8': 'b', '@': 'a', '$': 's', 'vv': 'w', 'rn': 'm'
}


def extract_urls(text):
    """Extracts all URLs and domain-like links from raw text."""
    if not text:
        return []
    url_pattern = re.compile(
        r'(?:https?://|ftp://|www\.)[^\s<>"\'{}|\\^`]+|(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|xyz|top|click|info|gov|edu|io|co|me|biz|ru|work|buzz|club|cf|gq|ml|tk)[/\w\.\?%&=~#\-]*',
        re.IGNORECASE
    )
    matches = url_pattern.findall(text)
    # Clean matches (remove trailing punctuation like period or comma)
    cleaned = []
    for match in matches:
        cleaned_url = match.rstrip('.,;:)!?"\'')
        if not cleaned_url.startswith(('http://', 'https://', 'ftp://')):
            cleaned_url = 'http://' + cleaned_url
        if cleaned_url not in cleaned:
            cleaned.append(cleaned_url)
    return cleaned


def calculate_entropy(text):
    """Calculates the Shannon Entropy of a string to detect randomized/DGA domains."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
    return round(entropy, 3)


def levenshtein_distance(s1, s2):
    """Computes the Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def normalize_homoglyphs(text):
    """Replaces common leetspeak/homoglyphs with standard ASCII characters."""
    normalized = text.lower()
    for k, v in HOMOGLYPH_MAP.items():
        normalized = normalized.replace(k, v)
    return normalized


def check_typosquatting(domain):
    """
    Detects if the domain attempts to spoof or impersonate a known brand
    via Levenshtein distance, homoglyph replacement, or brand compounding.
    """
    domain_lower = domain.lower()
    # Strip TLD and port
    domain_clean = re.sub(r':\d+$', '', domain_lower)
    parts = domain_clean.split('.')
    
    # Extract main domain label (e.g. 'paypal' in 'paypal.com' or 'paypal' in 'paypal.evil.com')
    main_label = parts[-2] if len(parts) >= 2 else parts[0]
    subdomains = parts[:-2] if len(parts) >= 2 else []

    detected_brands = []

    # 1. Subdomain brand deception (e.g., paypal.com.attacker.com)
    for sub in subdomains:
        for brand in TARGETED_BRANDS:
            if brand in sub:
                detected_brands.append({
                    "brand": brand,
                    "technique": "Subdomain Deception (Brand in subdomain)",
                    "severity": "HIGH",
                    "details": f"Subdomain '{sub}' impersonates '{brand}', but the actual apex domain is '{'.'.join(parts[-2:])}'"
                })

    # 2. Hyphenated brand prefix/suffix (e.g., login-paypal.com or apple-verification.com)
    for brand in TARGETED_BRANDS:
        if brand in main_label and main_label != brand:
            detected_brands.append({
                "brand": brand,
                "technique": "Brand Compounding / Hyphenation",
                "severity": "HIGH",
                "details": f"Domain label '{main_label}' combines target brand '{brand}' with secondary words to trick users"
            })

    # 3. Levenshtein edit distance & Homoglyph test
    norm_label = normalize_homoglyphs(main_label)
    for brand in TARGETED_BRANDS:
        if main_label == brand:
            # Genuine brand domain or exact match
            continue

        # Exact homoglyph match (e.g. paypa1 -> paypal, g00gle -> google)
        if norm_label == brand:
            detected_brands.append({
                "brand": brand,
                "technique": "Homoglyph / Character Substitution",
                "severity": "CRITICAL",
                "details": f"Domain '{main_label}' uses character substitution to mimic target brand '{brand}'"
            })
            continue

        dist = levenshtein_distance(main_label, brand)
        norm_dist = levenshtein_distance(norm_label, brand)
        if (1 <= dist <= 2 or 1 <= norm_dist <= 2) and len(main_label) >= 4:
            detected_brands.append({
                "brand": brand,
                "technique": "Typosquatting / Visual Lookalike",
                "severity": "CRITICAL",
                "details": f"Domain '{main_label}' is dangerously close to '{brand}' (Levenshtein distance: {min(dist, norm_dist)})"
            })

    return detected_brands


def analyze_url(url):
    """
    Performs comprehensive security and lexical analysis of a single URL.
    Returns structured metrics, risk score, flags, and actionable explanations.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname or parsed.netloc.split(':')[0]
    path = parsed.path or ""
    query = parsed.query or ""

    flags = []
    risk_score = 0  # 0 to 100

    # 1. IP Address check (e.g., http://192.168.1.50/login)
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    is_ip = bool(re.match(ip_pattern, hostname))
    if is_ip:
        risk_score += 40
        flags.append({
            "type": "IP_HOST",
            "name": "Host is Raw IP Address",
            "severity": "HIGH",
            "description": f"URL uses raw IP '{hostname}' instead of a registered domain name, typical of malicious hosting servers."
        })

    # 2. Suspicious TLD check
    tld = hostname.split('.')[-1].lower() if '.' in hostname else ""
    if tld in SUSPICIOUS_TLDS:
        risk_score += 25
        flags.append({
            "type": "SUSPICIOUS_TLD",
            "name": f"High-Abuse TLD (.{tld})",
            "severity": "MEDIUM",
            "description": f"Top-level domain '.{tld}' is statistically heavily abused by phishing operators and spam syndicates."
        })

    # 3. URL Shortener check
    is_shortener = hostname.lower() in URL_SHORTENERS
    if is_shortener:
        risk_score += 20
        flags.append({
            "type": "URL_SHORTENER",
            "name": "URL Shortener Detected",
            "severity": "MEDIUM",
            "description": f"Domain '{hostname}' is a link shortener that conceals the true final destination."
        })

    # 4. Excessive Subdomains (Domain Nesting)
    subdomain_count = len(hostname.split('.')) - 2 if len(hostname.split('.')) > 2 else 0
    if subdomain_count >= 3:
        risk_score += 20
        flags.append({
            "type": "EXCESSIVE_SUBDOMAINS",
            "name": "Deep Subdomain Nesting",
            "severity": "MEDIUM",
            "description": f"Domain contains {subdomain_count} subdomains, a common tactic to bypass basic filters or impersonate brand paths."
        })

    # 5. Domain Shannon Entropy (DGA / Random string check)
    domain_body = hostname.split('.')[0] if '.' in hostname else hostname
    entropy = calculate_entropy(domain_body)
    if entropy >= 3.8 and len(domain_body) >= 10:
        risk_score += 25
        flags.append({
            "type": "HIGH_ENTROPY",
            "name": "High Domain Entropy (Potential DGA)",
            "severity": "HIGH",
            "description": f"Domain body '{domain_body}' has high character randomness (entropy {entropy:.2f}), suggesting an automated Domain Generation Algorithm."
        })

    # 6. Typosquatting / Brand Impersonation
    typo_results = check_typosquatting(hostname)
    for typo in typo_results:
        risk_score += 35
        flags.append({
            "type": "TYPOSQUATTING",
            "name": f"Brand Impersonation ({typo['brand'].capitalize()})",
            "severity": typo["severity"],
            "description": typo["details"]
        })

    # 7. Credential / Phishing Keywords in Path or Query
    url_tokens = set(re.findall(r'\b[a-zA-Z]{3,}\b', (path + " " + query).lower()))
    matched_keywords = url_tokens.intersection(SENSITIVE_KEYWORDS)
    if matched_keywords:
        risk_score += min(len(matched_keywords) * 10, 25)
        flags.append({
            "type": "SENSITIVE_KEYWORDS",
            "name": "Phishing Keywords in URL Path",
            "severity": "MEDIUM",
            "description": f"URL path/query includes security-sensitive terms: {', '.join(sorted(matched_keywords))}"
        })

    # 8. User-info '@' Symbol Deception
    if '@' in parsed.netloc:
        risk_score += 45
        flags.append({
            "type": "AT_SYMBOL_DECEPTION",
            "name": "Authentication '@' Symbol Deception",
            "severity": "CRITICAL",
            "description": "URL utilizes the '@' symbol to mislead users into believing they are visiting the domain before the '@', while the browser connects to the domain after it."
        })

    # 9. Insecure Protocol
    if parsed.scheme == 'http':
        risk_score += 10
        flags.append({
            "type": "INSECURE_HTTP",
            "name": "Unencrypted HTTP Protocol",
            "severity": "LOW",
            "description": "The URL uses unencrypted plain HTTP instead of HTTPS."
        })

    # 10. Non-Standard Port
    if parsed.port and parsed.port not in [80, 443]:
        risk_score += 15
        flags.append({
            "type": "NON_STANDARD_PORT",
            "name": f"Unusual Port (:{parsed.port})",
            "severity": "MEDIUM",
            "description": f"URL connects on non-standard web port {parsed.port}."
        })

    # Normalize risk score to 0-100
    final_score = min(max(risk_score, 0), 100)
    verdict = "SAFE" if final_score < 30 else ("SUSPICIOUS" if final_score < 65 else "MALICIOUS")

    return {
        "url": url,
        "hostname": hostname,
        "protocol": parsed.scheme or "http",
        "tld": tld,
        "subdomain_count": subdomain_count,
        "entropy": entropy,
        "is_ip": is_ip,
        "is_shortener": is_shortener,
        "risk_score": final_score,
        "verdict": verdict,
        "flags": flags
    }


def analyze_all_urls(text):
    """Extracts and analyzes all URLs found in the given text."""
    urls = extract_urls(text)
    results = [analyze_url(u) for u in urls]
    
    # Calculate overall aggregate URL threat score
    if not results:
        return {
            "urls_detected": 0,
            "results": [],
            "max_risk_score": 0,
            "aggregate_verdict": "NO_URLS"
        }

    max_risk = max(r["risk_score"] for r in results)
    aggregate_verdict = "SAFE" if max_risk < 30 else ("SUSPICIOUS" if max_risk < 65 else "MALICIOUS")

    return {
        "urls_detected": len(results),
        "results": results,
        "max_risk_score": max_risk,
        "aggregate_verdict": aggregate_verdict
    }


if __name__ == "__main__":
    sample_text = "Check http://paypal.com.verify-billing-secure.xyz/login?id=891 and also http://192.168.1.1:8080/reset"
    res = analyze_all_urls(sample_text)
    print(f"Detected {res['urls_detected']} URLs. Aggregate Verdict: {res['aggregate_verdict']}, Max Risk: {res['max_risk_score']}")
    for r in res["results"]:
        print(f" - {r['url']}: {r['verdict']} ({r['risk_score']}%) Flags: {len(r['flags'])}")
