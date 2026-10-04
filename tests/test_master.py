from datetime import datetime
import json

from app.cases import Case
from app.master import analyze_case
from app.schemas import Alert, Event


class FakeFunction:
    def __init__(self, name, arguments):
        self.name = name
        self.arguments = arguments


class FakeCall:
    def __init__(self, call_id, name, arguments):
        self.id = call_id
        self.function = FakeFunction(name, arguments)


class FakeMessage:
    def __init__(self, calls):
        self.content = ""
        self.tool_calls = calls


class FakeChoice:
    def __init__(self, message):
        self.message = message


class FakeResponse:
    def __init__(self, message):
        self.choices = [FakeChoice(message)]
        self.usage = type(
            "Usage",
            (),
            {"total_tokens": 100},
        )()


class FakeCompletions:
    def create(self, **kwargs):
        self.kwargs = kwargs

        return FakeResponse(
            FakeMessage(
                [
                    FakeCall(
                        "1",
                        "list_emissaries",
                        "{}",
                    )
                ]
            )
        )


class FakeClient:
    def __init__(self):
        self.chat = type(
            "Chat",
            (),
            {
                "completions": FakeCompletions()
            },
        )()


def make_alert(
    alert_id,
    detector,
    src_ip,
    severity="P3",
):
    return Alert(
        id=alert_id,
        detector=detector,
        title=f"{detector} alert",
        src_ip=src_ip,
        first_seen=datetime(2026, 10, 3, 9, 0),
        last_seen=datetime(2026, 10, 3, 9, 1),
        count=1,
        severity=severity,
        score=50,
    )


def test_master_context_sees_correlated_case():
    a1 = make_alert(
        "A1",
        "bruteforce",
        "203.0.113.10",
    )

    a2 = make_alert(
        "A2",
        "portscan",
        "203.0.113.10",
    )

    case = Case(
        id="CASE-001",
        alerts=[a1, a2],
    )

    assert case.id == "CASE-001"
    assert len(case.alerts) == 2
    assert case.src_ips == ["203.0.113.10"]


def test_master_can_start_case_investigation():
    alert = make_alert(
        "A1",
        "bruteforce",
        "203.0.113.10",
    )

    case = Case(
        id="CASE-001",
        alerts=[alert],
    )

    result = analyze_case(
        case,
        events=[],
        alerts=[alert],
        client=FakeClient(),
        max_rounds=1,
    )

    assert result.case_id == "CASE-001"
    assert result.rounds == 1
    assert result.trace[0]["tool"] == "list_emissaries"


def test_master_dispatches_emissary_then_finalizes():
    alert = make_alert(
        "A1",
        "bruteforce",
        "203.0.113.10",
        severity="P2",
    )

    event = Event(
        ts=datetime(2026, 10, 3, 9, 0),
        source_type="auth",
        src_ip="203.0.113.10",
        user="root",
        action="login_failed",
        status="failed",
        message="failed login",
        raw="failed login",
    )

    case = Case(
        id="CASE-001",
        alerts=[alert],
    )

    class SequentialCompletions:
        def __init__(self):
            self.calls = 0

        def create(self, **kwargs):
            self.calls += 1

            if self.calls == 1:
                return FakeResponse(
                    FakeMessage(
                        [
                            FakeCall(
                                "1",
                                "dispatch_emissary",
                                json.dumps(
                                    {
                                        "emissary": "auth",
                                        "question": (
                                            "Investigate whether this "
                                            "authentication activity is suspicious."
                                        ),
                                    }
                                ),
                            )
                        ]
                    )
                )

            return FakeResponse(
                FakeMessage(
                    [
                        FakeCall(
                            "2",
                            "finalize_case",
                            json.dumps(
                                {
                                    "case_id": "CASE-001",
                                    "priority": "P2",
                                    "verdict": "true_positive",
                                    "confidence": "high",
                                    "title": "Authentication attack",
                                    "summary": (
                                        "The authentication activity "
                                        "requires investigation."
                                    ),
                                    "key_evidence": [
                                        "Source IP 203.0.113.10",
                                        "Brute-force detector raised an alert",
                                    ],
                                    "emissaries_consulted": [
                                        "auth"
                                    ],
                                    "recommended_actions": [
                                        (
                                            "Review the source IP and "
                                            "affected account."
                                        )
                                    ],
                                    "reasoning": (
                                        "The authentication specialist "
                                        "was consulted."
                                    ),
                                }
                            ),
                        )
                    ]
                )
            )

    fake_client = FakeClient()
    fake_client.chat.completions = SequentialCompletions()

    result = analyze_case(
        case,
        events=[event],
        alerts=[alert],
        client=fake_client,
        max_rounds=3,
    )

    assert result.fallback is False
    assert result.case_id == "CASE-001"
    assert result.assessment.verdict == "true_positive"
    assert result.assessment.priority == "P2"

    tools_called = [
        entry["tool"]
        for entry in result.trace
    ]

    assert "dispatch_emissary" in tools_called
    assert "finalize_case" in tools_called

    dispatch = next(
        entry
        for entry in result.trace
        if entry["tool"] == "dispatch_emissary"
    )

    assert dispatch["arguments"]["emissary"] == "auth"
