"""
India Fraud Detector — Detect UPI fraud, bank phishing, and Aadhaar scams.

Specialized for Indian fintech and government service fraud detection.

Usage:
    pip install sentinelx
    python india_fraud_detector.py
"""

import sys
sys.path.insert(0, "../sdk")

from sentinelx import SentinelX

API_URL = "https://sentinelx402-production.up.railway.app"

# Suspicious domains from SMS/WhatsApp messages
suspicious_messages = [
    {"text": "Your SBI account is blocked. Verify at sbi-online-banking-verify.com", "domain": "sbi-online-banking-verify.com"},
    {"text": "Claim Paytm cashback: upi-paytm-cashback-claim.com", "domain": "upi-paytm-cashback-claim.com"},
    {"text": "Update Aadhaar eKYC: aadhaar-ekyc-verification.in", "domain": "aadhaar-ekyc-verification.in"},
    {"text": "PhonePe reward: phonepe-reward-collect.xyz", "domain": "phonepe-reward-collect.xyz"},
    {"text": "Income tax refund: income-tax-refund-claim.in", "domain": "income-tax-refund-claim.in"},
    {"text": "Flipkart sale: flipkart.com", "domain": "flipkart.com"},
    {"text": "HDFC NetBanking update: hdfc-netbanking-secure.xyz", "domain": "hdfc-netbanking-secure.xyz"},
    {"text": "Jio 5G recharge: jio-5g-unlimited-recharge.xyz", "domain": "jio-5g-unlimited-recharge.xyz"},
]


def main():
    client = SentinelX(base_url=API_URL)

    print("India Fraud Detector")
    print("Scanning SMS/WhatsApp messages for fraud...")
    print("=" * 60)

    frauds = []

    for msg in suspicious_messages:
        risk = client.domain_lookup(msg["domain"])

        if risk.is_malicious:
            frauds.append(msg)
            india_tags = [t for t in risk.tags if t in ("india", "upi", "banking", "government", "ecommerce", "telecom")]
            category = india_tags[1] if len(india_tags) > 1 else "fraud"
            print(f"  FRAUD   [{category:10}] {msg['domain']} (score: {risk.risk_score})")
            print(f"          Message: \"{msg['text'][:60]}...\"")
        else:
            print(f"  SAFE    {msg['domain']} (score: {risk.risk_score})")

    print("=" * 60)
    print(f"Result: {len(frauds)}/{len(suspicious_messages)} messages are fraudulent")
    if frauds:
        print("\nRecommendation: Block these domains and report to CERT-In")

    client.close()


if __name__ == "__main__":
    main()
