from __future__ import annotations

from app.detectors.webattacks import detect_webattacks
from app.emissaries.base import Emissary
from app.schemas import Alert, Event


class WebEmissary(Emissary):
    name = "web"

    description = (
        "Web security specialist that investigates HTTP activity "
        "for SQL injection, traversal, XSS and command injection."
    )

    source_types = ("web",)

    def investigate(
        self,
        events: list[Event],
        question: str | None = None,
    ) -> list[Alert]:
        web_events = [
            event
            for event in events
            if event.source_type == "web"
        ]

        return detect_webattacks(web_events)