import json
import runpy
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from app.agent.agent import analyze_alert
from app.agent.tools import MAX_EVENTS, CaseContext, execute_tool
from app.detectors import run_all
from app.parsers import parse_text

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"


@pytest.fixture(scope="session", autouse=True)
def make_samples():
    if not (SAMPLES / "auth.log").exists():
        runpy.run_path(str(SAMPLES / "gen_logs.py"), run_name="__main__")


def load(name, stype):
    events, _ = parse_text((SAMPLES / name).read_text(), stype)
    alerts = run_all(events)
    return alerts, CaseContext(events, alerts)


# ---- a scripted stand-in for the LLM client: no network, no cost ----
def call(i, name, args):
    return NS(id=f"call_{i}", function=NS(name=name, arguments=args if isinstance(args, str) else json.dumps(args)))


def reply(calls=None, content=None):
    return NS(choices=[NS(message=NS(content=content, tool_calls=calls or None))],
              usage=NS(total_tokens=100))


class FakeClient:
    def __init__(self, script):
        self.script, self.seen = list(script), []
        self.chat = NS(completions=NS(create=self._create))

    def _create(self, **kw):
        self.seen.append(kw["messages"])
        return self.script.pop(0) if self.script else self.script_default()

    def script_default(self):
        return reply([call(99, "enrich_ip", {"ip": "203.0.113.50"})])


GOOD = dict(title="SSH brute force then compromise", severity="P1", verdict="true_positive",
            confidence="high", summary="25 failures then a success from 203.0.113.50.",
            evidence=["25 failed logins in 3 minutes", "success for admin"], mitre=["T1110", "t1078", "bogus"],
            recommended_actions=["Block 203.0.113.50 after verification", "Reset the admin password"],
            reasoning="Burst followed by success from a listed IP.")


def test_happy_path():
    alerts, ctx = load("auth.log", "auth")
    fake = FakeClient([
        reply([call(1, "enrich_ip", {"ip": "203.0.113.50"}), call(2, "query_events", {"src_ip": "203.0.113.50", "limit": 5})]),
        reply([call(3, "finalize_incident", GOOD)]),
    ])
    run = analyze_alert(alerts[0], ctx, client=fake, model="fake")
    assert not run.fallback and run.rounds == 2
    assert run.incident.verdict == "true_positive" and run.incident.mitre == ["T1110", "T1078"]
    assert [t["tool"] for t in run.trace] == ["enrich_ip", "query_events", "finalize_incident"]
    assert '"in_local_blocklist": true' in run.trace[0]["result"]
    # the tool output really went back to the model
    assert any(m.get("role") == "tool" for m in fake.seen[1])


def test_invalid_finalize_is_fed_back_then_accepted():
    alerts, ctx = load("auth.log", "auth")
    bad = {k: v for k, v in GOOD.items() if k != "verdict"}
    fake = FakeClient([reply([call(1, "finalize_incident", bad)]), reply([call(2, "finalize_incident", GOOD)])])
    run = analyze_alert(alerts[0], ctx, client=fake, model="fake")
    assert not run.fallback and run.rounds == 2
    assert "failed validation" in run.trace[0]["result"]


def test_guardrails_block_downgrade_of_p1():
    alerts, ctx = load("auth.log", "auth")
    assert alerts[0].severity == "P1"
    sneaky = dict(GOOD, severity="P4", verdict="likely_false_positive")
    run = analyze_alert(alerts[0], ctx, client=FakeClient([reply([call(1, "finalize_incident", sneaky)])]), model="fake")
    assert run.incident.severity == "P2" and run.incident.verdict == "needs_review"
    assert len(run.incident.guardrail_notes) == 2


def test_model_that_never_finalizes_falls_back():
    alerts, ctx = load("auth.log", "auth")
    fake = FakeClient([reply(content="all good"), reply(content="really")])
    run = analyze_alert(alerts[0], ctx, client=fake, model="fake")
    assert run.fallback and run.incident.verdict == "needs_review"


def test_round_limit_falls_back():
    alerts, ctx = load("auth.log", "auth")
    run = analyze_alert(alerts[0], ctx, client=FakeClient([]), model="fake", max_rounds=3)
    assert run.fallback and run.rounds == 3 and len(run.trace) == 3


def test_bad_json_arguments_do_not_crash():
    alerts, ctx = load("auth.log", "auth")
    fake = FakeClient([reply([call(1, "query_events", "{not json")]), reply([call(2, "finalize_incident", GOOD)])])
    run = analyze_alert(alerts[0], ctx, client=fake, model="fake")
    assert not run.fallback and "invalid arguments" in run.trace[0]["result"]


def test_tools_are_bounded_and_read_only():
    alerts, ctx = load("web.log", "web")
    r = execute_tool("query_events", {"limit": 9999}, ctx)
    assert r["returned"] <= MAX_EVENTS and r["matched"] > MAX_EVENTS
    assert "error" in execute_tool("rm_rf", {}, ctx)
    assert execute_tool("lookup_mitre", {"technique_id": "T1190"}, ctx)["name"].startswith("Exploit")
    assert execute_tool("enrich_ip", {"ip": "10.0.0.5"}, ctx)["internal"] is True


def test_false_positive_sample_is_an_internal_single_account_alert():
    alerts, _ = load("fp_auth.log", "auth")
    assert len(alerts) == 1 and alerts[0].src_ip == "10.0.0.25"
    assert alerts[0].users == ["alice"] and alerts[0].severity == "P2"
    assert alerts[0].details["successful_logins"][0]["user"] == "alice"


def test_provider_extra_content_is_echoed_back():
    """Gemini 3.x needs its thought signature returned with the tool call."""
    alerts, ctx = load("auth.log", "auth")
    sig = {"google": {"thought_signature": "abc123"}}
    tc = call(1, "enrich_ip", {"ip": "203.0.113.50"})
    tc.extra_content = sig
    fake = FakeClient([reply([tc]), reply([call(2, "finalize_incident", GOOD)])])
    run = analyze_alert(alerts[0], ctx, client=fake, model="fake")
    assert not run.fallback
    second_request = fake.seen[1]
    assistant = [m for m in second_request if m["role"] == "assistant"][0]
    assert assistant["tool_calls"][0]["extra_content"] == sig
