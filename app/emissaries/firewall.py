from __future__ import annotations

from app.detectors.portscan import detect_portscan
from app.emissaries.base import Emissary
from app.schemas import Alert, Event


class FirewallEmissary(Emissary):
    name = "firewall"
    description = (
        "Firewall specialist that investigates network connection "
        "patterns, including port scanning activity."
    )
    source_types = ("firewall",)

    def investigate(
        self,
        events: list[Event],
        question: str | None = None,
    ) -> list[Alert]:
        firewall_events = [
            event for event in events
            if event.source_type == "firewall"
        ]

        return detect_portscan(firewall_events)