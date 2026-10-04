from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from app.schemas import Alert


@dataclass
class Case:
    """A group of related alerts representing one security situation."""

    id: str
    alerts: list[Alert] = field(default_factory=list)

    @property
    def first_seen(self) -> datetime:
        return min(alert.first_seen for alert in self.alerts)

    @property
    def last_seen(self) -> datetime:
        return max(alert.last_seen for alert in self.alerts)

    @property
    def src_ips(self) -> list[str]:
        return sorted(
            {
                alert.src_ip
                for alert in self.alerts
                if alert.src_ip
            }
        )

    @property
    def users(self) -> list[str]:
        return sorted(
            {
                user
                for alert in self.alerts
                for user in alert.users
                if user
            }
        )

    @property
    def detectors(self) -> list[str]:
        return sorted(
            {alert.detector for alert in self.alerts}
        )

    @property
    def timeline(self) -> list[dict]:
        timeline = []

        for alert in self.alerts:
            timeline.append(
                {
                    "timestamp": alert.first_seen,
                    "detector": alert.detector,
                    "title": alert.title,
                    "severity": alert.severity,
                    "src_ip": alert.src_ip,
                    "count": alert.count,
                }
            )

        return sorted(
            timeline,
            key=lambda item: item["timestamp"],
        )


def _alert_keys(alert: Alert) -> set[tuple[str, str]]:
    """Return correlation keys available on an alert."""

    keys: set[tuple[str, str]] = set()

    if alert.src_ip:
        keys.add(("ip", alert.src_ip))

    for user in alert.users:
        if user:
            keys.add(("user", user))

    return keys


def _related(
    alert_a: Alert,
    alert_b: Alert,
    window: timedelta,
) -> bool:
    """Return True when two alerts share an entity and overlap in time."""

    keys_a = _alert_keys(alert_a)
    keys_b = _alert_keys(alert_b)

    if not keys_a.intersection(keys_b):
        return False

    return (
        alert_a.first_seen <= alert_b.last_seen + window
        and alert_b.first_seen <= alert_a.last_seen + window
    )


def correlate_alerts(
    alerts: list[Alert],
    window_minutes: int = 10,
) -> list[Case]:
    """
    Group related alerts into security Cases.

    Correlation is deterministic:
    - shared source IP or user
    - activity within the configured time window
    """

    if not alerts:
        return []

    window = timedelta(minutes=window_minutes)

    ordered = sorted(
        alerts,
        key=lambda alert: alert.first_seen,
    )

    groups: list[list[Alert]] = []

    for alert in ordered:
        matching_groups = [
            group
            for group in groups
            if any(
                _related(alert, existing, window)
                for existing in group
            )
        ]

        if not matching_groups:
            groups.append([alert])
            continue

        primary = matching_groups[0]
        primary.append(alert)

        # Merge groups when the new alert connects them.
        for other in matching_groups[1:]:
            primary.extend(other)
            groups.remove(other)

    cases = []

    for index, group in enumerate(groups, start=1):
        group.sort(key=lambda alert: alert.first_seen)

        cases.append(
            Case(
                id=f"CASE-{index:03d}",
                alerts=group,
            )
        )

    return cases