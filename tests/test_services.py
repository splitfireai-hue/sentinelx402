"""Unit tests for scoring algorithms."""

from __future__ import annotations

from app.services.scoring import compute_cve_risk, compute_domain_risk


class TestDomainScoring:
    def test_known_phishing_domain_scores_high(self):
        result = compute_domain_risk("login-secure-paypal.com")
        assert result.score >= 60
        assert result.threat_type in ("phishing", "suspicious")

    def test_benign_domain_scores_low(self):
        result = compute_domain_risk("google.com")
        assert result.score < 40

    def test_suspicious_tld_increases_score(self):
        base = compute_domain_risk("example.com")
        suspicious = compute_domain_risk("example.xyz")
        assert suspicious.score > base.score

    def test_multiple_keywords_increase_score(self):
        result = compute_domain_risk("secure-login-verify-account.com")
        assert result.score >= 50

    def test_brand_impersonation_detected(self):
        result = compute_domain_risk("paypal-security-update.xyz")
        assert result.score >= 70
        assert result.confidence >= 0.4

    def test_hyphenated_domains_score_higher(self):
        plain = compute_domain_risk("something.com")
        hyphenated = compute_domain_risk("some-thing-here.com")
        assert hyphenated.score >= plain.score


class TestCVEScoring:
    def test_critical_cvss_yields_critical_risk(self):
        result = compute_cve_risk(9.8)
        assert result.risk_level == "critical"
        assert result.patch_urgency == "critical"

    def test_low_cvss_yields_low_risk(self):
        result = compute_cve_risk(2.5)
        assert result.risk_level == "low"
        assert result.patch_urgency == "low"

    def test_exploit_increases_probability(self):
        without = compute_cve_risk(7.5, has_exploit=False)
        with_exploit = compute_cve_risk(7.5, has_exploit=True)
        assert with_exploit.exploit_probability > without.exploit_probability

    def test_exploit_with_high_cvss_critical_urgency(self):
        result = compute_cve_risk(8.0, has_exploit=True)
        assert result.patch_urgency == "critical"

    def test_ransomware_cwe_flagged(self):
        result = compute_cve_risk(9.0, cwe_id="CWE-787")
        assert result.ransomware_risk is True

    def test_non_ransomware_cwe_not_flagged(self):
        result = compute_cve_risk(9.0, cwe_id="CWE-79")
        assert result.ransomware_risk is False

    def test_low_cvss_no_ransomware_even_with_cwe(self):
        result = compute_cve_risk(3.0, cwe_id="CWE-787")
        assert result.ransomware_risk is False

    def test_medium_cvss(self):
        result = compute_cve_risk(5.5)
        assert result.risk_level == "medium"
        assert result.patch_urgency == "medium"

    def test_exploit_probability_capped_at_one(self):
        result = compute_cve_risk(9.5, has_exploit=True)
        assert result.exploit_probability <= 1.0
