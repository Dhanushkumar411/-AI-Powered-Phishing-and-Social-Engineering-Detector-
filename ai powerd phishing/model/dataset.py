"""
Curated and synthesized high-quality dataset for Phishing and Social Engineering detection.
Includes diverse phishing attacks (credential theft, BEC, fake invoices, banking alerts, delivery scams)
and legitimate communications (work emails, tech updates, orders, receipts, newsletters).
"""

import random

# Base curated dataset with realistic, high-fidelity phishing and legitimate samples
CURATED_SAMPLES = [
    # ------------------ PHISHING: CREDENTIAL THEFT & ACCOUNT EXPOSURE ------------------
    {
        "text": "URGENT: Your Microsoft 365 account password will expire in 2 hours. To keep your current password and avoid disruption to your Outlook mailbox, please verify your credentials immediately at http://login-microsoft365-security-portal.xyz/verify-login. Failure to update will result in permanent account suspension.",
        "label": 1,
        "category": "credential_theft"
    },
    {
        "text": "Security Alert: We detected an unauthorized login attempt to your Google Account from an unrecognized device in Moscow, Russia. If this was not you, please secure your account immediately by verifying your identity here: http://accounts-google-verify.top/recovery. Your session will terminate in 15 minutes.",
        "label": 1,
        "category": "credential_theft"
    },
    {
        "text": "Apple Support: Your Apple ID was used to purchase an iPhone 15 Pro ($1,199.00) on the Apple Store. If you did not authorize this transaction, cancel it immediately to prevent credit card billing: http://apple-id-management-alert.click/cancel-order",
        "label": 1,
        "category": "credential_theft"
    },
    {
        "text": "Your Netflix membership is on hold because of a payment error. Please update your billing details and credit card information to resume streaming without interruption: http://netflix-billing-update-center.work/payment",
        "label": 1,
        "category": "credential_theft"
    },
    {
        "text": "IT Service Desk Notice: All employees are required to migrate their company single sign-on (SSO) credentials before 5:00 PM today due to mandatory security patching. Click the migration link: http://intranet-sso-portal-auth.buzz/login",
        "label": 1,
        "category": "credential_theft"
    },
    {
        "text": "Warning: Your mailbox storage has exceeded 98% of the allowed quota (49.8 GB / 50 GB). You will not be able to send or receive new emails. Increase your quota for free: http://webmail-storage-upgrade.tk/validate",
        "label": 1,
        "category": "credential_theft"
    },
    {
        "text": "Instagram Copyright Infringement: A post on your profile infringes on trademark copyright laws. Your profile will be permanently deleted within 24 hours unless you submit an objection form here: http://instagram-copyright-appeals.cf/form",
        "label": 1,
        "category": "credential_theft"
    },
    {
        "text": "LinkedIn Security: You have 7 unread messages and 3 connection requests waiting. Verify your email address to unlock your incoming messages: http://linkedin-messages-sync.cc/auth",
        "label": 1,
        "category": "credential_theft"
    },

    # ------------------ PHISHING: FINANCIAL, BANKING & PAYPAL ------------------
    {
        "text": "PayPal Alert: We have restricted your account due to unusual transaction activity. We noticed a charge of $849.99 to Best Buy. Click here immediately to review and dispute this charge: http://paypal.com.verification-center-security.net/dispute?id=94812",
        "label": 1,
        "category": "banking"
    },
    {
        "text": "Chase Bank Fraud Prevention: A wire transfer of $4,500.00 to an international beneficiary is pending your approval. If you did not authorize this transfer, click decline immediately: http://chase-security-fraud-alert.info/transfer-stop",
        "label": 1,
        "category": "banking"
    },
    {
        "text": "Wells Fargo Alert: Your debit card ending in 4109 has been temporarily deactivated due to repeated incorrect PIN entries. Reactivate your card now by confirming your online banking credentials and SSN: http://wellsfargo-debit-reactivation.biz/login",
        "label": 1,
        "category": "banking"
    },
    {
        "text": "Bank of America Notice: New security protocols require all online banking customers to re-authenticate their identity and update security questions. Access your portal: http://bofa-customer-reauth.top/identity",
        "label": 1,
        "category": "banking"
    },
    {
        "text": "Important Tax Notice from Internal Revenue Service (IRS): You are eligible for an unclaimed tax refund of $1,420.50 from the 2023 fiscal year. Submit your direct deposit bank details to receive funds: http://irs-gov-tax-refund-portal.click/claim",
        "label": 1,
        "category": "banking"
    },

    # ------------------ PHISHING: BUSINESS EMAIL COMPROMISE (BEC) & CEO FRAUD ------------------
    {
        "text": "Are you at your desk right now? I am currently tied up in an executive board meeting and need you to urgently process a wire transfer to a vendor. Please do not call as I cannot pick up. Reply back immediately so I can send the invoice and bank routing details. Thanks, CEO.",
        "label": 1,
        "category": "bec_fraud"
    },
    {
        "text": "Quick favor - I need you to purchase 10 Apple iTunes gift cards ($100 each) for client appreciation rewards today. Scratch the back and send photos of the codes to me as soon as possible. I will reimburse your expense report by end of day.",
        "label": 1,
        "category": "bec_fraud"
    },
    {
        "text": "Urgent Request: Payroll direct deposit update. Please change my direct deposit routing number for this week's paycheck to the following account number: 981240182. Let me know once updated so I can confirm.",
        "label": 1,
        "category": "bec_fraud"
    },
    {
        "text": "CONFIDENTIAL: Acquisition documents. We are finalizing an undisclosed strategic merger. Please review the attached contract and non-disclosure agreement strictly confidentially: http://secure-corporate-docs-sharepoint.download/NDA_2026.pdf.exe",
        "label": 1,
        "category": "bec_fraud"
    },

    # ------------------ PHISHING: FAKE INVOICES & RENEWAL SCAMS ------------------
    {
        "text": "Geek Squad Order Confirmation: Thank you for renewing your Total Tech Support 3-year subscription. Your bank account will be automatically debited $499.99 within 24 hours. If you wish to cancel or dispute this auto-debit, call our cancellation desk immediately at +1-888-555-0199.",
        "label": 1,
        "category": "fake_invoice"
    },
    {
        "text": "Norton LifeLock: Your annual antivirus renewal for $379.00 has been processed successfully. Transaction ID: #NL-991823. If you did not place this order, download your refund cancellation form: http://norton-antivirus-billing-desk.fit/refund",
        "label": 1,
        "category": "fake_invoice"
    },
    {
        "text": "McAfee Total Protection: Invoice INV-84920 for $299.95 has been charged to your VISA card. To dispute this charge and request an immediate refund, contact support or click here: http://mcafee-refund-support-desk.top/cancel",
        "label": 1,
        "category": "fake_invoice"
    },

    # ------------------ PHISHING: PACKAGE DELIVERY & SHIPPING ------------------
    {
        "text": "DHL Express Tracking Alert: We attempted to deliver your parcel (Tracking #DHL-9281903) but nobody was home to sign. A customs handling fee of $2.49 is pending. Please pay the customs fee within 24 hours to schedule re-delivery: http://dhl-express-redelivery-notice.xyz/track",
        "label": 1,
        "category": "delivery_scam"
    },
    {
        "text": "USPS Notification: Your package delivery has been suspended due to an incomplete home address. Please update your postal delivery address and pay the $1.95 redelivery fee: http://usps-address-confirmation-portal.club/update",
        "label": 1,
        "category": "delivery_scam"
    },
    {
        "text": "FedEx Delivery Manager: We were unable to deliver your package #FX-339182 today. Your item has been returned to the local sorting depot. Please confirm your details: http://fedex-parcel-dispatch-center.work/confirm",
        "label": 1,
        "category": "delivery_scam"
    },

    # ------------------ PHISHING: LOTTERY, ADVANCE FEE & CRYPTO ------------------
    {
        "text": "CONGRATULATIONS! You have been selected as the grand winner of the Coca-Cola International Lottery 2026. You have won a lump sum payout of $2,500,000.00 USD. To claim your prize, send your full name, passport copy, and processing fee of $150 to claim-officer@lottery-payouts.ru",
        "label": 1,
        "category": "advance_fee"
    },
    {
        "text": "URGENT: Bar. David Williams from Barclays Bank London. I am managing an unclaimed estate of 15.5 Million Pounds left by an investor who died without an heir. I propose to transfer 40% of this fund into your account if you assist as next-of-kin. Reply confidentially with your full telephone and banking details.",
        "label": 1,
        "category": "advance_fee"
    },
    {
        "text": "Binance & Elon Musk Bitcoin Giveaway: To celebrate the new crypto milestone, we are distributing 5,000 BTC! Send between 0.05 BTC and 2 BTC to the official promotion wallet address and instantly receive DOUBLE (2X) back to your wallet! Hurry, only 142 BTC remaining: http://crypto-giveaway-binance-double.top/btc",
        "label": 1,
        "category": "crypto_scam"
    },

    # ------------------ LEGITIMATE (HAM): WORKPLACE & ENGINEERING ------------------
    {
        "text": "Hi team, please find the meeting agenda for tomorrow's sprint retrospective attached. We'll be discussing the Q3 deployment timeline, CI pipeline improvements, and reviewing outstanding Jira backlog tickets. Let me know if you want to add any talking points before 10 AM.",
        "label": 0,
        "category": "workplace"
    },
    {
        "text": "Pull Request #342: Refactored authentication middleware to use JWT tokens. All unit tests and integration tests passed on GitHub Actions. Could you take a look and approve when you have a moment? Thanks! https://github.com/company/auth-service/pull/342",
        "label": 0,
        "category": "workplace"
    },
    {
        "text": "Reminder: The weekly engineering all-hands meeting starts in 15 minutes in Conference Room B and via Google Meet. Today's agenda includes the product roadmap update from the VP of Product and a demo of the new analytics dashboard.",
        "label": 0,
        "category": "workplace"
    },
    {
        "text": "Hi Alex, here is the draft presentation for Thursday's client sync. Please review slides 4 through 8 regarding the system architecture and let me know if the latency benchmarks look accurate. Best regards, Sarah.",
        "label": 0,
        "category": "workplace"
    },
    {
        "text": "Good morning everyone. Just a reminder that our annual company benefits enrollment period opens next Monday, November 3rd, through our official Workday portal. Feel free to reach out to the HR benefits desk if you have questions.",
        "label": 0,
        "category": "workplace"
    },
    {
        "text": "Hey Chris, lunch at 12:30 at the taco place down the street? Mark and Dave are coming along too. Let me know if that works for you.",
        "label": 0,
        "category": "personal"
    },
    {
        "text": "Hi team, the scheduled database migration on the staging environment completed successfully at 04:00 UTC with zero downtime. You can resume running your automated end-to-end tests.",
        "label": 0,
        "category": "workplace"
    },

    # ------------------ LEGITIMATE (HAM): RECEIPTS, NOTIFICATIONS & E-COMMERCE ------------------
    {
        "text": "Your Amazon.com order #112-9842103-7721943 has shipped! Your package contains 'Python Crash Course, 3rd Edition' and is scheduled for delivery tomorrow by 8:00 PM. You can track your shipment anytime on Amazon: https://www.amazon.com/your-orders",
        "label": 0,
        "category": "ecommerce"
    },
    {
        "text": "Thank you for your ride with Uber this morning. Total charged to your Visa ending in 8192 was $24.50. View your full trip receipt, download PDF tax invoice, or rate your driver in the Uber mobile app.",
        "label": 0,
        "category": "ecommerce"
    },
    {
        "text": "Your monthly electric and utility bill is now ready to view. Total amount due: $118.42 due on November 15, 2026. Automatic autopay is scheduled from your checking account. Thank you for choosing Clean Energy Power.",
        "label": 0,
        "category": "billing"
    },
    {
        "text": "Flight Confirmation - Delta Air Lines Flight DL 482 from San Francisco (SFO) to New York (JFK). Confirmation Code: HF78KL. Check-in online 24 hours prior to departure at https://www.delta.com or using the Fly Delta app.",
        "label": 0,
        "category": "travel"
    },
    {
        "text": "Your GitHub monthly invoice for organization 'open-source-devs' is available. Plan: GitHub Team ($40.00/month). Your receipt has been charged to the credit card on file. View billing history in account settings.",
        "label": 0,
        "category": "billing"
    },
    {
        "text": "Medium Daily Digest: 5 Python architectural patterns every senior engineer should master. Read the full curated stories from top writers on software engineering and data science today.",
        "label": 0,
        "category": "newsletter"
    },
    {
        "text": "Your doctor's appointment reminder: You have a routine check-up scheduled with Dr. Emily Watson tomorrow at 2:30 PM at Downtown Medical Clinic. Reply 'C' to confirm or call our office at 555-0144 to reschedule.",
        "label": 0,
        "category": "personal"
    },
    {
        "text": "Thank you for shopping at Trader Joe's. Here is your digital receipt for transaction #88391 at Store #402. Total: $64.18. Keep this email for your personal expense records.",
        "label": 0,
        "category": "ecommerce"
    }
]

# Variations and templates to synthetically expand the dataset while preserving realism and high diversity
PHISHING_TEMPLATES = [
    # Credential Harvesting
    "CRITICAL ALERT: Your {service} account will be terminated in {hours} hours due to unverified profile information. Click {url} to authenticate and prevent account suspension.",
    "URGENT NOTICE: Suspicious login from {location} detected on your {service} profile. Confirm your password immediately to protect your files: {url}",
    "Action Required: We could not process your recurring payment for {service}. Update your payment method and card details at {url} within 24 hours to avoid cancellation.",
    "Notification from {service} Security: Unrecognized sign-in attempt blocked. To keep your account secure, please reset your password now: {url}",
    "Final Warning: Your {service} subscription is set to be cancelled today. Retain your active benefits by updating your billing information here: {url}",
    
    # Financial / Banking
    "Alert from {bank}: A wire transfer of ${amount} to an offshore account is waiting for your authorization. If you did not make this transaction, visit {url} immediately.",
    "Important Notice: Your {bank} checking account has been restricted due to suspicious debit transactions. Verify your SSN and account number to restore full access: {url}",
    "Payment Confirmation: You authorized a payment of ${amount} to {merchant}. If this is unauthorized, cancel transaction immediately at {url}",
    "Tax Advisory: You have a pending tax refund of ${amount} waiting to be disbursed. Provide your bank account details for direct deposit: {url}",

    # Delivery scams
    "Delivery Exception: Parcel #{tracking} cannot be delivered due to invalid delivery address. Re-confirm your shipping address and pay the ${fee} re-dispatch charge: {url}",
    "Courier Alert: Your shipment #{tracking} is held at customs warehouse. Please pay the customs duty fee of ${fee} within 24 hours: {url}",

    # CEO / BEC fraud
    "Urgent: I am stepping into a meeting with clients and need you to handle an urgent wire of ${amount} for vendor payment. Send me a quick reply once you get this so I can provide the wiring instructions.",
    "Need your assistance quickly: Can you purchase {num} gift cards (${amount} each) for an employee incentive presentation? Reply back with the codes as soon as possible.",

    # Fake invoice
    "Invoice #{inv_num} for ${amount} has been charged to your account for {service} subscription renewal. If you did not authorize this, call our customer care immediately or dispute at {url}",
    "Thank you for your order! Your purchase of {service} software (${amount}) is complete. If this purchase was made in error, visit {url} to claim an instant full refund."
]

HAM_TEMPLATES = [
    # Workplace & Engineering
    "Hi team, just a reminder that the Q{quarter} planning session is scheduled for tomorrow at {time}. Please make sure your team's slide deck is updated in Google Drive.",
    "Code Review Request: I just pushed commit {hash} for feature '{feature}'. Could you review the PR and check unit test coverage when you get a chance? https://github.com/org/repo/pull/{pr_num}",
    "Meeting notes from today's sync on {feature}: We agreed on the database schema migration plan. Target release date is next Tuesday. Let me know if anyone has questions.",
    "Hi {name}, following up on our discussion yesterday regarding the client onboarding workflow. I've attached the architecture diagram and requirements document for your feedback.",
    "Sprint backlog grooming is scheduled for Thursday at {time}. Please review the assigned tickets in Jira and estimate story points prior to the call.",
    "Office announcement: The building maintenance team will be testing the fire alarm systems this Friday between {time} and {time}. No evacuation is needed.",
    
    # E-commerce, Travel & Daily Notifications
    "Your order #{order_id} from {retailer} has been confirmed! We will send you another email with tracking details as soon as your items leave our warehouse.",
    "Your package from {retailer} has arrived! It was delivered to your front porch. View order details or start a return at https://www.{retailer_domain}/orders",
    "Reservation confirmation: Your table for {guests} at {restaurant} is booked for Friday at {time}. If you need to make changes, manage your booking on OpenTable.",
    "Your monthly statement for account ending in {last4} is now available online. Log in securely to your online banking portal to view your statement.",
    "Here is your weekly summary of tech news: Top discussions on Python 3.13, machine learning workflows, and cloud architecture optimizations.",
    "Thank you for attending the webinar '{webinar_title}'. The slides and recorded session link have been published on our community portal."
]

SERVICES = ["Microsoft 365", "Google Workspace", "Apple ID", "Dropbox", "Slack", "Zoom", "Office 365", "DocuSign", "Adobe Cloud"]
BANKS = ["Chase Bank", "Wells Fargo", "Bank of America", "Citibank", "Capital One", "PNC Bank", "TD Bank", "PayPal"]
MERCHANTS = ["Best Buy", "Target Electronics", "eBay Seller", "Coinbase", "Apple Store", "Crypto Exchange"]
LOCATIONS = ["Moscow, Russia", "Lagos, Nigeria", "Beijing, China", "Frankfurt, Germany", "Kiev, Ukraine", "Sao Paulo, Brazil"]
BAD_DOMAINS = [
    "http://secure-login-portal-auth.xyz/verify",
    "http://account-verification-system.top/login",
    "http://update-billing-info-service.click/auth",
    "http://security-alert-center.work/protect",
    "http://banking-auth-confirmation.buzz/reset",
    "http://service-quota-warning.tk/upgrade",
    "http://support-helpdesk-agent.cf/session",
    "http://paypal.com.account-protection-update.net/login",
    "http://chase.com.security-client-alert.info/action"
]

RETAILERS = [
    ("Amazon", "amazon.com"),
    ("Target", "target.com"),
    ("Best Buy", "bestbuy.com"),
    ("Apple", "apple.com"),
    ("Home Depot", "homedepot.com"),
    ("Nike", "nike.com")
]

NAMES = ["David", "Jessica", "Michael", "Sarah", "Alex", "Emily", "Robert", "Rachel", "Carlos"]
FEATURES = ["user authentication flow", "payment gateway integration", "reporting dashboard", "OAuth2 SSO", "caching layer", "search index optimization"]
RESTAURANTS = ["Bistro Central", "Olive & Oak", "Trattoria Milano", "Sakura Sushi", "The Capital Grille"]
WEBINARS = ["Scaling Distributed Microservices", "Modern ML with Scikit-Learn", "Defensive Cybersecurity Essentials", "Cloud Architecture Best Practices"]


def generate_extended_dataset(num_phishing=300, num_ham=300, seed=42):
    """Generates an extended balanced dataset combining curated and template-generated examples."""
    random.seed(seed)
    dataset = list(CURATED_SAMPLES)

    # Generate Phishing samples
    for _ in range(num_phishing):
        template = random.choice(PHISHING_TEMPLATES)
        text = template.format(
            service=random.choice(SERVICES),
            bank=random.choice(BANKS),
            merchant=random.choice(MERCHANTS),
            location=random.choice(LOCATIONS),
            url=random.choice(BAD_DOMAINS),
            hours=random.choice([1, 2, 4, 12, 24]),
            amount=f"{random.randint(150, 4800)}.{random.randint(10, 99):02d}",
            tracking=f"TRK{random.randint(1000000, 9999999)}",
            fee=f"{random.choice([1.49, 2.99, 3.50, 4.25])}",
            num=random.choice([5, 8, 10, 15]),
            inv_num=f"INV-{random.randint(10000, 99999)}"
        )
        dataset.append({
            "text": text,
            "label": 1,
            "category": "phishing_synthetic"
        })

    # Generate Ham samples
    for _ in range(num_ham):
        template = random.choice(HAM_TEMPLATES)
        retailer, retailer_domain = random.choice(RETAILERS)
        text = template.format(
            quarter=random.choice([1, 2, 3, 4]),
            time=f"{random.randint(9, 16)}:{random.choice(['00', '15', '30', '45'])}",
            hash=f"{random.randint(1000000, 9999999):x}",
            feature=random.choice(FEATURES),
            pr_num=random.randint(100, 950),
            name=random.choice(NAMES),
            order_id=f"{random.randint(100, 999)}-{random.randint(1000000, 9999999)}",
            retailer=retailer,
            retailer_domain=retailer_domain,
            guests=random.choice([2, 4, 6]),
            restaurant=random.choice(RESTAURANTS),
            last4=f"{random.randint(1000, 9999)}",
            webinar_title=random.choice(WEBINARS)
        )
        dataset.append({
            "text": text,
            "label": 0,
            "category": "ham_synthetic"
        })

    random.shuffle(dataset)
    return dataset


if __name__ == "__main__":
    data = generate_extended_dataset()
    phish_count = sum(1 for d in data if d["label"] == 1)
    ham_count = sum(1 for d in data if d["label"] == 0)
    print(f"Dataset generated successfully! Total: {len(data)}, Phishing: {phish_count}, Legitimate: {ham_count}")
