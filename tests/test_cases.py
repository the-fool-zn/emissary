from datetime import datetime, timedelta

from app.cases import correlate_alerts
from app.schemas import Alert


def make_alert(
    detector: str,
    src_ip: str | None,
    first_seen: datetime,
    *,
    users: list[str] | None = None,
) -> Alert:
    return Alert(
        detector=detector,
        title=f"{detector} alert",
        src_ip=src_ip,
        users=users or [],
        first_seen=first_seen,
        last_seen=first_seen + timedelta(minutes=1),
        count=1,
        severity="P3",
        score=50,
    )


def test_related_alerts_from_same_ip_form_one_case():
    start = datetime(2026, 10, 3, 9, 0, 0)

    alerts = [
        make_alert(
            "portscan",
            "203.0.113.99",
            start,
        ),
        make_alert(
            "bruteforce",
            "203.0.113.99",
            start + timedelta(minutes=2),
        ),
        make_alert(
            "webattack",
            "203.0.113.99",
            start + timedelta(minutes=4),
        ),
    ]

    cases = correlate_alerts(alerts)

    assert len(cases) == 1
    assert len(cases[0].alerts) == 3
    assert cases[0].src_ips == ["203.0.113.99"]
    assert cases[0].detectors == [
        "bruteforce",
        "portscan",
        "webattack",
    ]


def test_unrelated_ips_form_separate_cases():
    start = datetime(2026, 10, 3, 9, 0, 0)

    alerts = [
        make_alert(
            "portscan",
            "203.0.113.10",
            start,
        ),
        make_alert(
            "bruteforce",
            "203.0.113.20",
            start + timedelta(minutes=1),
        ),
    ]

    cases = correlate_alerts(alerts)

    assert len(cases) == 2


def test_alerts_outside_time_window_are_separate():
    start = datetime(2026, 10, 3, 9, 0, 0)

    alerts = [
        make_alert(
            "portscan",
            "203.0.113.99",
            start,
        ),
        make_alert(
            "bruteforce",
            "203.0.113.99",
            start + timedelta(minutes=20),
        ),
    ]

    cases = correlate_alerts(
        alerts,
        window_minutes=10,
    )

    assert len(cases) == 2


def test_shared_user_can_correlate_alerts():
    start = datetime(2026, 10, 3, 9, 0, 0)

    alerts = [
        make_alert(
            "bruteforce",
            None,
            start,
            users=["root"],
        ),
        make_alert(
            "webattack",
            None,
            start + timedelta(minutes=2),
            users=["root"],
        ),
    ]

    cases = correlate_alerts(alerts)

    assert len(cases) == 1
    assert cases[0].users == ["root"]


def test_case_timeline_is_chronological():
    start = datetime(2026, 10, 3, 9, 0, 0)

    alerts = [
        make_alert(
            "webattack",
            "203.0.113.99",
            start + timedelta(minutes=5),
        ),
        make_alert(
            "portscan",
            "203.0.113.99",
            start,
        ),
    ]

    cases = correlate_alerts(alerts)

    timeline = cases[0].timeline

    assert timeline[0]["detector"] == "portscan"
    assert timeline[1]["detector"] == "webattack"


def test_empty_alerts_produce_no_cases():
    assert correlate_alerts([]) == []