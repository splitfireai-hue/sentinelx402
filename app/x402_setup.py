"""x402 payment middleware configuration.

Launch pricing (lower to drive adoption):
- Threat endpoints: $0.01 per call
- CVE lookup:       $0.03 per call
- Premium feeds:    $0.05 per call
"""

from app.config import settings

MAINNET_NETWORK = "eip155:8453"
_ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"


def validate_x402_config() -> list:
    """Return a list of fatal misconfiguration messages (empty == safe to enable).

    Guards against the silent-failure mode where x402 is turned on but payments
    can never settle (e.g. mainnet network pointed at the testnet-only facilitator,
    or missing CDP auth), which would 402 every caller with no way to pay.
    """
    issues = []
    if not settings.X402_ENABLED:
        return issues

    is_mainnet = settings.NETWORK_ID == MAINNET_NETWORK
    facilitator = settings.FACILITATOR_URL or ""

    if is_mainnet and "x402.org" in facilitator:
        issues.append(
            "NETWORK_ID is Base mainnet but FACILITATOR_URL is the testnet-only "
            "x402.org facilitator. Set FACILITATOR_URL=https://api.cdp.coinbase.com/platform/v2/x402"
        )
    if is_mainnet and not (settings.CDP_API_KEY_ID and settings.CDP_API_KEY_SECRET):
        issues.append(
            "Base mainnet settlement requires the Coinbase CDP facilitator. "
            "Set CDP_API_KEY_ID and CDP_API_KEY_SECRET in the environment."
        )
    if settings.WALLET_ADDRESS in ("", _ZERO_ADDRESS):
        issues.append("WALLET_ADDRESS is unset/zero — payments would be unroutable.")
    return issues


def create_x402_server():
    from x402.http import FacilitatorConfig, HTTPFacilitatorClient
    from x402.mechanisms.evm.exact import ExactEvmServerScheme
    from x402.server import x402ResourceServer

    facilitator = HTTPFacilitatorClient(
        FacilitatorConfig(url=settings.FACILITATOR_URL)
    )
    server = x402ResourceServer(facilitator)
    server.register(settings.NETWORK_ID, ExactEvmServerScheme())
    return server


def get_routes_config():
    from x402.http import PaymentOption
    from x402.http.types import RouteConfig

    wallet = settings.WALLET_ADDRESS
    network = settings.NETWORK_ID

    def _option(price: str) -> list:
        return [
            PaymentOption(
                scheme="exact",
                pay_to=wallet,
                price=price,
                network=network,
            )
        ]

    return {
        "GET /api/v1/threats/lookup": RouteConfig(
            accepts=_option("$0.01"),
            description="Domain threat risk lookup",
            mime_type="application/json",
        ),
        "GET /api/v1/threats/ip": RouteConfig(
            accepts=_option("$0.01"),
            description="IP reputation check",
            mime_type="application/json",
        ),
        "GET /api/v1/threats/feed": RouteConfig(
            accepts=_option("$0.05"),
            description="Latest threat indicators feed",
            mime_type="application/json",
        ),
        "GET /api/v1/cves/{cve_id}": RouteConfig(
            accepts=_option("$0.03"),
            description="CVE risk analysis",
            mime_type="application/json",
        ),
        "GET /api/v1/cves/recent": RouteConfig(
            accepts=_option("$0.05"),
            description="Recent critical CVEs",
            mime_type="application/json",
        ),
        "GET /api/v1/cves/search": RouteConfig(
            accepts=_option("$0.03"),
            description="Search CVEs by keyword",
            mime_type="application/json",
        ),
    }
