from __future__ import annotations

from app.emissaries.base import Emissary


class EmissaryRegistry:
    """
    Registry of specialist Emissaries available to Master.
    """

    def __init__(self) -> None:
        self._emissaries: dict[str, Emissary] = {}

    def register(self, emissary: Emissary) -> None:
        if emissary.name in self._emissaries:
            raise ValueError(
                f"Emissary already registered: {emissary.name}"
            )

        self._emissaries[emissary.name] = emissary

    def get(self, name: str) -> Emissary:
        try:
            return self._emissaries[name]
        except KeyError:
            raise KeyError(f"Unknown Emissary: {name}") from None

    def list(self) -> list[dict]:
        return [
            emissary.capabilities()
            for emissary in self._emissaries.values()
        ]

    def names(self) -> list[str]:
        return list(self._emissaries.keys())