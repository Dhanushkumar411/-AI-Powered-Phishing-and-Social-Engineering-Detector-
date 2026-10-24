"""
Social Engineering & Psychological Trigger Engine.
Analyzes text for emotional coercion, artificial urgency, authority impersonation,
fear tactics, financial bait, and action-forcing directives.
"""

import re

# Comprehensive psychological categories and trigger regex patterns
PSYCHOLOGICAL_TRIGGERS = {
    "urgency": {
        "title": "Artificial Urgency & Time Scarcity",
        "description": "Pressures victim to react impulsively without thinking or verifying.",
        "weight": 1.4,
        "patterns": [
            r"\b(urgent(?:ly)?|immediate(?:ly)?|right now|hurry|asap|at once)\b",
            r"\b(within\s+\d+\s+(?:hours?|minutes?|days?)|in\s+\d+\s+(?:hours?|minutes?))\b",
            r"\b(expires?\s+(?:today|soon|in\s+\d+\s+hours?)|limited\s+time|final\s+(?:warning|notice|reminder))\b",
            r"\b(act\s+now|don'?t\s+delay|time\s+is\s+running\s+out|deadline)\b",
            r"\b(action\s+required\s+immediately|before\s+it'?s\s+too\s+late)\b"
        ]
    },
    "fear_coercion": {
        "title": "Fear, Intimidation & Threat",
        "description": "Manufactures panic regarding account closure, legal punishment, or security breaches.",
        "weight": 1.5,
        "patterns": [
            r"\b(account\s+(?:suspended|restricted|terminated|frozen|locked|disabled|deactivated))\b",
            r"\b(unauthorized\s+(?:access|login|activity|transaction|charge))\b",
            r"\b(security\s+(?:breach|alert|incident|compromise|threat))\b",
            r"\b(legal\s+action|lawsuit|law\s+enforcement|police|arrest|fines?|penalty)\b",
            r"\b(permanent\s+(?:deletion|closure|loss)|will\s+be\s+deleted)\b",
            r"\b(unrecognized\s+device|fraud\s+prevention|suspicious\s+activity)\b"
        ]
    },
    "authority": {
        "title": "Authority & Pretexting",
        "description": "Impersonates trusted power figures, corporate executives, or official institutions.",
        "weight": 1.2,
        "patterns": [
            r"\b(ceo|cfo|executive|board\s+of\s+directors|director|president|vp)\b",
            r"\b(it\s+support|helpdesk|system\s+administrator|security\s+team|hr\s+department|payroll)\b",
            r"\b(internal\s+revenue\s+service|irs|fbi|homeland\s+security|department\s+of\s+justice)\b",
            r"\b(fraud\s+investigation\s+unit|compliance\s+officer|official\s+notice)\b",
            r"\b(microsoft\s+support|apple\s+support|google\s+security\s+team|bank\s+manager)\b"
        ]
    },
    "financial_greed": {
        "title": "Financial Enticement & Greed",
        "description": "Lures victims with unearned money, lotteries, crypto windfalls, or massive discounts.",
        "weight": 1.3,
        "patterns": [
            r"\b(congratulations|grand\s+winner|selected\s+to\s+receive|lottery|jackpot)\b",
            r"\b(unclaimed\s+(?:funds?|estate|prize|reward|refund|inheritance))\b",
            r"\b(\$\s*[\d,]{4,}|\b\d+\s*(?:million|billion)\s*(?:dollars|usd|pounds|gbp|eur))\b",
            r"\b(free\s+gift\s+card|bitcoin\s+giveaway|double\s+your\s+crypto|100%\s+guaranteed\s+profit)\b",
            r"\b(direct\s+deposit\s+waiting|tax\s+refund\s+approved|cash\s+bonus)\b"
        ]
    },
    "action_forcing": {
        "title": "Action-Forcing & Credential Harvesting",
        "description": "Directs the victim to execute an immediate high-risk action (click link, enter credentials, transfer funds).",
        "weight": 1.4,
        "patterns": [
            r"\b(click\s+(?:here|the\s+link|below|this\s+link)|open\s+the\s+attachment)\b",
            r"\b(verify\s+(?:your\s+)?(?:identity|account|credentials|password|email))\b",
            r"\b(update\s+(?:your\s+)?(?:billing|payment|credit\s+card|information|profile))\b",
            r"\b(confirm\s+(?:your\s+)?(?:password|pin|ssn|social\s+security|bank\s+details))\b",
            r"\b(wire\s+transfer|send\s+gift\s+cards?|scratch\s+the\s+back|buy\s+itunes\s+card)\b",
            r"\b(download\s+(?:invoice|receipt|document|form))\b"
        ]
    },
    "secrecy_curiosity": {
        "title": "Secrecy, Isolation & Curiosity",
        "description": "Demands strict secrecy to prevent the victim from consulting coworkers or security professionals.",
        "weight": 1.1,
        "patterns": [
            r"\b(strictly\s+confidential|keep\s+this\s+(?:between\s+us|secret|confidential))\b",
            r"\b(do\s+not\s+(?:call|tell|mention\s+this\s+to\s+anyone|discuss))\b",
            r"\b(undisclosed\s+(?:merger|acquisition|matter)|private\s+request)\b",
            r"\b(private\s+photos?|unrecognized\s+invoice|look\s+at\s+this)\b"
        ]
    }
}


def analyze_social_engineering(text):
    """
    Scans the text for social engineering cues and psychological triggers.
    Returns categorized score breakdowns, matched spans, and an aggregate vulnerability index.
    """
    if not text:
        return {
            "vulnerability_score": 0,
            "overall_threat": "NONE",
            "categories": {},
            "matched_triggers": [],
            "trigger_count": 0
        }

    categories_result = {}
    matched_triggers = []
    total_weighted_score = 0.0
    active_categories_count = 0

    for cat_id, cat_info in PSYCHOLOGICAL_TRIGGERS.items():
        cat_matches = []
        for pattern in cat_info["patterns"]:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                phrase = match.group(0)
                start, end = match.span()
                cat_matches.append({
                    "phrase": phrase,
                    "start": start,
                    "end": end,
                    "category": cat_id
                })
                matched_triggers.append({
                    "phrase": phrase,
                    "category_title": cat_info["title"],
                    "category": cat_id,
                    "start": start,
                    "end": end
                })

        # Calculate category score (0-100) based on match frequency and weight
        raw_score = min(len(cat_matches) * 35, 100)
        weighted_cat_score = raw_score * cat_info["weight"]

        categories_result[cat_id] = {
            "title": cat_info["title"],
            "description": cat_info["description"],
            "score": round(raw_score, 1),
            "match_count": len(cat_matches),
            "matches": [m["phrase"] for m in cat_matches]
        }

        if raw_score > 0:
            total_weighted_score += weighted_cat_score
            active_categories_count += 1

    # Normalize aggregate vulnerability score to 0 - 100 scale
    # If multiple categories are combined (e.g. Urgency + Fear + Action-Forcing), compound the score
    if active_categories_count >= 3:
        total_weighted_score *= 1.25
    elif active_categories_count >= 2:
        total_weighted_score *= 1.10

    normalized_vulnerability = min(round(total_weighted_score / 3.0, 1), 100.0)

    # Threat tier
    if normalized_vulnerability < 25:
        overall_threat = "LOW"
    elif normalized_vulnerability < 60:
        overall_threat = "MODERATE"
    elif normalized_vulnerability < 80:
        overall_threat = "HIGH"
    else:
        overall_threat = "CRITICAL"

    # Sort matched triggers by start offset
    matched_triggers.sort(key=lambda x: x["start"])

    return {
        "vulnerability_score": normalized_vulnerability,
        "overall_threat": overall_threat,
        "active_tactics_count": active_categories_count,
        "categories": categories_result,
        "matched_triggers": matched_triggers,
        "trigger_count": len(matched_triggers)
    }


if __name__ == "__main__":
    sample = "URGENT: Your account is suspended due to unauthorized access. Click here immediately to verify your identity within 2 hours or legal action will follow."
    result = analyze_social_engineering(sample)
    print(f"Vulnerability Score: {result['vulnerability_score']}% ({result['overall_threat']})")
    print(f"Triggers detected: {result['trigger_count']}")
    for trig in result["matched_triggers"]:
        print(f" - [{trig['category']}] '{trig['phrase']}'")
