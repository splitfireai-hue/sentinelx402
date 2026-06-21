"""Tests for the x402 / fiat-billing coexistence rule.

The paywall must charge ONLY anonymous callers; authenticated (already-billed)
API-key customers must bypass it. See app.main._x402_should_bypass.
"""

from __future__ import annotations

import importlib

from app.main import _x402_should_bypass
from app.x402_setup import validate_x402_config, x402_is_active


def _h(**kwargs) -> dict:
    """Build a raw ASGI header dict (bytes keys/values)."""
    return {k.lower().encode(): v.encode() for k, v in kwargs.items()}


def test_anonymous_request_is_charged():
    assert _x402_should_bypass(_h(), billing_enabled=True) is False


def test_api_key_header_bypasses_paywall():
    assert _x402_should_bypass(_h(**{"x-api-key": "sk_live_abc"}), billing_enabled=True) is True


def test_bearer_token_bypasses_paywall():
    assert _x402_should_bypass(_h(authorization="Bearer sk_live_abc"), billing_enabled=True) is True


def test_bearer_is_case_insensitive():
    assert _x402_should_bypass(_h(authorization="bEaReR x"), billing_enabled=True) is True


def test_non_bearer_authorization_is_charged():
    # A Basic auth header is not a billing key — still anonymous to x402.
    assert _x402_should_bypass(_h(authorization="Basic Zm9v"), billing_enabled=True) is False


def test_no_bypass_when_billing_disabled():
    # Without billing, keys are never validated, so a forged header must NOT
    # be allowed to dodge payment.
    assert _x402_should_bypass(_h(**{"x-api-key": "anything"}), billing_enabled=False) is False


def test_validate_passes_when_x402_disabled():
    # validate_x402_config short-circuits to empty when the flag is off.
    assert validate_x402_config() == []


def test_x402_inactive_when_disabled():
    # Default test env has X402_ENABLED=false.
    assert x402_is_active() is False


def test_x402_inactive_when_enabled_but_misconfigured(monkeypatch):
    # Enabled on mainnet with no facilitator creds / zero wallet -> config invalid
    # -> NOT active, so billing keeps enforcing the anon trial limit (no free leak).
    import app.config as cfg
    monkeypatch.setattr(cfg.settings, "X402_ENABLED", True)
    monkeypatch.setattr(cfg.settings, "NETWORK_ID", "eip155:8453")
    monkeypatch.setattr(cfg.settings, "FACILITATOR_URL", "https://x402.org/facilitator")
    monkeypatch.setattr(cfg.settings, "WALLET_ADDRESS", "0x" + "0" * 40)
    monkeypatch.setattr(cfg.settings, "CDP_API_KEY_ID", "")
    monkeypatch.setattr(cfg.settings, "CDP_API_KEY_SECRET", "")
    assert validate_x402_config(), "expected config issues"
    assert x402_is_active() is False


def test_x402_active_when_enabled_and_valid(monkeypatch):
    import app.config as cfg
    monkeypatch.setattr(cfg.settings, "X402_ENABLED", True)
    monkeypatch.setattr(cfg.settings, "NETWORK_ID", "eip155:8453")
    monkeypatch.setattr(cfg.settings, "FACILITATOR_URL", "https://api.cdp.coinbase.com/platform/v2/x402")
    monkeypatch.setattr(cfg.settings, "WALLET_ADDRESS", "0x" + "11" * 20)
    monkeypatch.setattr(cfg.settings, "CDP_API_KEY_ID", "id")
    monkeypatch.setattr(cfg.settings, "CDP_API_KEY_SECRET", "secret")
    assert validate_x402_config() == []
    assert x402_is_active() is True
