from __future__ import annotations

from app.detectors.bruteforce import detect_bruteforce
from app.emissaries.base import Emissary
from app.schemas import Alert, Event


class AuthEmissary(Emissary):
    name = "auth"
    description = (
        "Authentication specialist that investigates failed and successful "
        "login activity, including brute-force patterns."
    )
    source_types = ("auth",)

    def investigate(
        self,
        events: list[Event],
        question: str | None = None,
    ) -> list[Alert]:
        auth_events = [
            event for event in events
            if event.source_type == "auth"
        ]

        return detect_bruteforce(auth_events)