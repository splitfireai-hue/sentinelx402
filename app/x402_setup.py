"""x402 payment middleware configuration."""

from app.config import settings


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
            accepts=_option("$0.10"),
            description="Domain threat risk lookup",
            mime_type="application/json",
        ),
        "GET /api/v1/threats/ip": RouteConfig(
            accepts=_option("$0.10"),
            description="IP reputation check",
            mime_type="application/json",
        ),
        "GET /api/v1/threats/feed": RouteConfig(
            accepts=_option("$0.10"),
            description="Latest threat indicators feed",
            mime_type="application/json",
        ),
        "GET /api/v1/cves/{cve_id}": RouteConfig(
            accepts=_option("$0.25"),
            description="CVE risk analysis",
            mime_type="application/json",
        ),
        "GET /api/v1/cves/recent": RouteConfig(
            accepts=_option("$0.10"),
            description="Recent critical CVEs",
            mime_type="application/json",
        ),
        "GET /api/v1/cves/search": RouteConfig(
            accepts=_option("$0.10"),
            description="Search CVEs by keyword",
            mime_type="application/json",
        ),
    }
