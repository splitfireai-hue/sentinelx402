"""Risk scoring algorithms for threat intelligence and CVE analysis.

NOTE: This is a simplified reference implementation. The production
SentinelX402 service uses proprietary scoring models with additional
signals, brand datasets, and tuned thresholds not included here.
"""

import hashlib
import math
from dataclasses import dataclass

# Reference brand list (production uses an extended proprietary dataset)
POPULAR_BRANDS = [
    "paypal", "amazon", "microsoft", "apple", "google", "facebook",
    "netflix", "instagram", "linkedin", "coinbase", "binance",
]

SUSPICIOUS_TLDS = {
    ".xyz", ".click", ".info", ".cc", ".ws", ".top", ".tk", ".ml",
    ".ga", ".cf", ".gq", ".download", ".zip", ".mov",
}

SUSPICIOUS_KEYWORDS = [
    "login", "secure", "verify", "account", "update", "confirm",
    "auth", "billing", "alert", "recovery", "claim", "wallet",
]

RANSOMWARE_CWES = {
    "CWE-787", "CWE-416", "CWE-190", "CWE-20", "CWE-78",
    "CWE-119", "CWE-502", "CWE-94", "CWE-918",
}


@dataclass
class DomainRiskResult:
    score: float
    threat_type: str
    confidence: float


@dataclass
class CVERiskResult:
    exploit_probability: float
    patch_urgency: str
    ransomware_risk: bool
    risk_level: str


def _domain_entropy(domain: str) -> float:
    freq = {}
    for ch in domain:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(domain)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return _levenshtein(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def _brand_similarity(domain: str) -> float:
    domain_lower = domain.lower().split(".")[0]
    best = 0.0
    for brand in POPULAR_BRANDS:
        if brand in domain_lower:
            return 1.0
        dist = _levenshtein(domain_lower, brand)
        max_len = max(len(domain_lower), len(brand))
        sim = 1 - (dist / max_len) if max_len > 0 else 0
        best = max(best, sim)
    return best


def compute_domain_risk(domain: str) -> DomainRiskResult:
    """Compute risk score for a domain. Reference implementation."""
    score = 0.0
    signals = 0

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 25
            signals += 1
            break

    domain_lower = domain.lower()
    keyword_hits = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in domain_lower)
    score += min(keyword_hits * 12, 30)
    signals += min(keyword_hits, 3)

    brand_sim = _brand_similarity(domain)
    if brand_sim >= 0.7:
        score += 25
        signals += 1

    entropy = _domain_entropy(domain.split(".")[0])
    if entropy > 3.5:
        score += 10
        signals += 1

    if domain.count("-") >= 2:
        score += 10
        signals += 1

    hash_val = int(hashlib.md5(domain.encode()).hexdigest()[:8], 16) % 15
    score += hash_val

    score = min(score, 100)
    confidence = min(signals / 5, 1.0)

    if score >= 80:
        threat_type = "phishing"
    elif score >= 60:
        threat_type = "suspicious"
    elif score >= 40:
        threat_type = "potentially_unwanted"
    else:
        threat_type = "benign"

    return DomainRiskResult(score=round(score, 1), threat_type=threat_type, confidence=round(confidence, 2))


def compute_cve_risk(
    cvss_score: float,
    has_exploit: bool = False,
    cwe_id: str = "",
) -> CVERiskResult:
    """Compute enhanced risk analysis for a CVE. Reference implementation."""
    base_prob = cvss_score / 10.0
    if has_exploit:
        exploit_probability = min(base_prob + 0.3, 1.0)
    else:
        exploit_probability = base_prob * 0.7

    ransomware_risk = cwe_id in RANSOMWARE_CWES and cvss_score >= 7.0

    if cvss_score >= 9.0:
        risk_level = "critical"
    elif cvss_score >= 7.0:
        risk_level = "high"
    elif cvss_score >= 4.0:
        risk_level = "medium"
    else:
        risk_level = "low"

    if cvss_score >= 9.0 or (has_exploit and cvss_score >= 7.0):
        patch_urgency = "critical"
    elif cvss_score >= 7.0:
        patch_urgency = "high"
    elif cvss_score >= 4.0:
        patch_urgency = "medium"
    else:
        patch_urgency = "low"

    return CVERiskResult(
        exploit_probability=round(exploit_probability, 2),
        patch_urgency=patch_urgency,
        ransomware_risk=ransomware_risk,
        risk_level=risk_level,
    )
