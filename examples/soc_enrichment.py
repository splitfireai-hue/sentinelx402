"""
SOC Enrichment — Enrich security alerts with threat intelligence.

Simulates a SOC pipeline that receives IOCs (domains + IPs) from
firewall alerts and enriches them with risk scores.

Usage:
    pip install sentinelx
    python soc_enrichment.py
"""

import sys
sys.path.insert(0, "../sdk")

from sentinelx import SentinelX

API_URL = "https://sentinelx402-production.up.railway.app"

# Simulated alerts from SIEM / firewall
alerts = [
    {"type": "domain", "value": "cobaltstrike-beacon.duckdns.org", "source": "DNS logs"},
    {"type": "ip", "value": "185.220.101.42", "source": "Firewall"},
    {"type": "domain", "value": "secure-paypa1-login.com", "source": "Email gateway"},
    {"type": "ip", "value": "8.8.8.8", "source": "Firewall"},
    {"type": "domain", "value": "aadhaar-ekyc-verification.in", "source": "Web proxy"},
]


def main():
    client = SentinelX(base_url=API_URL)

    print("SOC Alert Enrichment")
    print("=" * 60)

    critical_alerts = []

    for alert in alerts:
        if alert["type"] == "domain":
            result = client.domain_lookup(alert["value"])
            score = result.risk_score
            threat = result.threat_type
            malicious = result.is_malicious
        else:
            result = client.ip_lookup(alert["value"])
            score = result.risk_score
            threat = ", ".join(result.threat_types) if result.threat_types else "clean"
            malicious = result.is_malicious

        severity = "CRITICAL" if score >= 90 else "HIGH" if score >= 70 else "LOW"

        print(f"  [{severity:8}] {alert['value']}")
        print(f"            Score: {score} | Threat: {threat} | Source: {alert['source']}")

        if malicious:
            critical_alerts.append({
                "indicator": alert["value"],
                "score": score,
                "threat": threat,
                "action": "BLOCK and investigate",
            })

    print("=" * 60)
    print(f"\nActionable alerts: {len(critical_alerts)}/{len(alerts)}")
    for a in critical_alerts:
        print(f"  -> {a['action']}: {a['indicator']} ({a['threat']}, score {a['score']})")

    client.close()


if __name__ == "__main__":
    main()
