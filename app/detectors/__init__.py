from typing import List

from app.schemas import Alert, Event
from .bruteforce import detect_bruteforce
from .portscan import detect_portscan
from .webattacks import detect_webattacks

DETECTORS = [detect_bruteforce, detect_portscan, detect_webattacks]


def run_all(events: List[Event]) -> List[Alert]:
    """Run every detector, rank by score (highest first), and give each alert an id."""
    alerts = [a for d in DETECTORS for a in d(events)]
    alerts.sort(key=lambda a: (-a.score, a.first_seen))
    for n, a in enumerate(alerts, 1):
        a.id = f"A-{n:04d}"
    return alerts
