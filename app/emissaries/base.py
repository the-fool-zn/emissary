from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from app.schemas import Alert, Event


class Emissary(ABC):
    """
    Standard contract for a specialist analyst.

    Master interacts with Emissaries through this interface instead
    of knowing how an individual detector works.
    """

    name: str
    description: str
    source_types: tuple[str, ...]

    @abstractmethod
    def investigate(
        self,
        events: list[Event],
        question: str | None = None,
    ) -> list[Alert]:
        """
        Investigate events and return specialist findings.

        `question` allows Master to give the specialist a focused
        investigation request.
        """
        raise NotImplementedError

    def capabilities(self) -> dict[str, Any]:
        """
        Machine-readable description that Master can inspect.
        """
        return {
            "name": self.name,
            "description": self.description,
            "source_types": list(self.source_types),
        }