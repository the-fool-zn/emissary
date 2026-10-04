from app.emissaries.defaults import build_default_registry


def test_default_registry_contains_all_emissaries():
    registry = build_default_registry()

    assert registry.names() == [
        "auth",
        "firewall",
        "web",
    ]


def test_default_registry_exposes_capabilities():
    registry = build_default_registry()

    capabilities = registry.list()

    assert {item["name"] for item in capabilities} == {
        "auth",
        "firewall",
        "web",
    }