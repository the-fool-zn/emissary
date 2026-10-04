from app.emissaries.auth import AuthEmissary
from app.emissaries.firewall import FirewallEmissary
from app.emissaries.registry import EmissaryRegistry
from app.emissaries.web import WebEmissary


def build_default_registry() -> EmissaryRegistry:
    registry = EmissaryRegistry()

    registry.register(AuthEmissary())
    registry.register(FirewallEmissary())
    registry.register(WebEmissary())

    return registry