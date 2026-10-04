from app.emissaries.base import Emissary
from app.emissaries.registry import EmissaryRegistry


class DummyEmissary(Emissary):
    name = "dummy"
    description = "Test specialist"
    source_types = ("test",)

    def investigate(self, events, question=None):
        return []


def test_emissary_exposes_standard_contract():
    emissary = DummyEmissary()

    capabilities = emissary.capabilities()

    assert capabilities["name"] == "dummy"
    assert capabilities["description"] == "Test specialist"
    assert capabilities["source_types"] == ["test"]


def test_emissary_accepts_investigation_question():
    emissary = DummyEmissary()

    result = emissary.investigate([], "What happened?")

    assert result == []


def test_registry_registers_and_finds_emissary():
    registry = EmissaryRegistry()
    emissary = DummyEmissary()

    registry.register(emissary)

    assert registry.get("dummy") is emissary
    assert registry.names() == ["dummy"]


def test_registry_lists_capabilities():
    registry = EmissaryRegistry()
    registry.register(DummyEmissary())

    result = registry.list()

    assert result == [
        {
            "name": "dummy",
            "description": "Test specialist",
            "source_types": ["test"],
        }
    ]


def test_registry_rejects_duplicate_emissary():
    registry = EmissaryRegistry()

    registry.register(DummyEmissary())

    try:
        registry.register(DummyEmissary())
        assert False, "Expected duplicate registration to fail"
    except ValueError as exc:
        assert "already registered" in str(exc)