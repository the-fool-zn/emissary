from datetime import datetime, timedelta

from app.emissaries.auth import AuthEmissary
from app.schemas import Event


def test_auth_emissary_detects_bruteforce():
    start = datetime(2026, 10, 3, 9, 0, 0)

    events = [
        Event(
            ts=start + timedelta(seconds=i * 5),
            source_type="auth",
            src_ip="203.0.113.99",
            user="root",
            action="login_failed",
            raw=f"failed login {i}",
        )
        for i in range(8)
    ]

    emissary = AuthEmissary()
    alerts = emissary.investigate(events)

    assert len(alerts) == 1
    assert alerts[0].detector == "bruteforce"
    assert alerts[0].src_ip == "203.0.113.99"


def test_auth_emissary_ignores_non_auth_events():
    event = Event(
        ts=datetime(2026, 10, 3, 9, 0, 0),
        source_type="web",
        src_ip="203.0.113.60",
        action="http_request",
        message="GET /",
        raw="web request",
    )

    emissary = AuthEmissary()

    assert emissary.investigate([event]) == []