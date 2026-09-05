"""Executable entry point and demonstration script for SIH 26106 Email Threat Detection.

Usage:
    python main.py
"""

import sys
from pathlib import Path

# Add workspace directory to python path for package resolution
workspace_dir = Path(__file__).resolve().parent
if str(workspace_dir) not in sys.path:
    sys.path.insert(0, str(workspace_dir))

from email_threat_detection.classifier import classify_email


def run_single_sample():
    """Run inference on the primary requested sample email and display the exact required output."""
    sample_subject = "Urgent account verification"
    sample_body = (
        "Your account will be suspended within 24 hours due to suspicious activity. "
        "Click here immediately to verify your identity: http://secure-banking-verify-alert.com/login"
    )

    result = classify_email(subject=sample_subject, body=sample_body)

    # Print exact required output format
    print(f"Prediction: {result.prediction.upper()}")
    print(f"Fraud probability: {result.fraud_probability:.3f}")
    print(f"Legitimate probability: {result.legitimate_probability:.3f}")
    print(f"Score: {result.score:.3f}")


def run_smoke_tests():
    """Run inference across the 6 smoke test scenarios to verify end-to-end functionality.
    
    Scenarios:
    1. Obviously legitimate business email
    2. Obvious phishing email asking for password
    3. Urgent account-verification phishing email
    4. Legitimate notification containing a URL
    5. Suspicious payment/fraud email
    6. Ordinary harmless email with no malicious language
    """
    print("\n" + "=" * 70)
    print("SIH 26106: Email Threat Detection - Smoke Test Scenarios")
    print("=" * 70)

    test_cases = [
        {
            "id": 1,
            "category": "Legitimate Business Email",
            "subject": "Project Sprint Review - Q3 Deliverables Update",
            "body": (
                "Hi Team, please find attached our weekly sprint notes. "
                "The retrospective will take place tomorrow at 10:00 AM in Conference Room B. "
                "Let me know if any topics need to be added to the agenda. Best regards, Rahul."
            )
        },
        {
            "id": 2,
            "category": "Password Phishing Attack",
            "subject": "ACTION REQUIRED: Your Email Password Has Expired",
            "body": (
                "Your corporate mailbox has expired. Reply to this email immediately with your "
                "current password and username to maintain mailbox access, or update credentials here: "
                "http://it-support-password-reset-portal.xyz/login"
            )
        },
        {
            "id": 3,
            "category": "Urgent Account Verification",
            "subject": "Urgent: Immediate Action Required - Account Suspended",
            "body": (
                "Dear customer, we detected an unauthorized transaction on your account. "
                "Your card and online access have been restricted. Verify your identity now at "
                "http://secure-bank-login-auth.com/verify or call +1-800-555-0199."
            )
        },
        {
            "id": 4,
            "category": "Legitimate Notification with URL",
            "subject": "Your monthly GitHub invoice is now available",
            "body": (
                "Hello, your monthly receipt for GitHub Pro is ready. "
                "You can view your billing settings and download the PDF at https://github.com/settings/billing. "
                "Thank you for your business."
            )
        },
        {
            "id": 5,
            "category": "Suspicious Payment / Invoice Fraud",
            "subject": "OVERDUE WIRE TRANSFER INVOICE #89421",
            "body": (
                "Attached is the urgent revised payment invoice of $9,450.00 USD. "
                "Our bank account details have changed due to an annual audit. "
                "Please process payment to the new routing details at: http://wire-remittance-update.top"
            )
        },
        {
            "id": 6,
            "category": "Harmless Everyday Email",
            "subject": "Lunch tomorrow?",
            "body": (
                "Hey! Are you free for lunch tomorrow around 1:00 PM at the new cafe? "
                "Let me know, see you soon!"
            )
        }
    ]

    for tc in test_cases:
        res = classify_email(subject=str(tc["subject"]), body=str(tc["body"]))
        status = "[FRAUD DETECTED]" if res.prediction == "fraudulent" else "[LEGITIMATE]"
        print(f"\nCase {tc['id']}: {tc['category']}")
        print(f"  Subject: '{tc['subject']}'")
        print(f"  Decision: {status} ({res.prediction})")
        print(f"  Fraud Prob: {res.fraud_probability:.4f} | Legit Prob: {res.legitimate_probability:.4f} | Score: {res.score:.4f}")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    # 1. Output the primary sample email prediction
    run_single_sample()

    # 2. Run the smoke test cases if requested via --smoke-test flag or default
    if "--smoke-tests" in sys.argv or "--all" in sys.argv:
        run_smoke_tests()
