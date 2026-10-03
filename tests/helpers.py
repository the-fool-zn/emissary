"""Scripted stand-in for the LLM client (no network, no cost). Used by the tests."""
import json
from types import SimpleNamespace as NS


def call(i, name, args):
    return NS(id=f"call_{i}", function=NS(name=name, arguments=args if isinstance(args, str) else json.dumps(args)))


def reply(calls=None, content=None):
    return NS(choices=[NS(message=NS(content=content, tool_calls=calls or None))], usage=NS(total_tokens=100))


class FakeClient:
    def __init__(self, script):
        self.script = list(script)
        self.chat = NS(completions=NS(create=self._create))

    def _create(self, **kw):
        return self.script.pop(0) if self.script else reply([call(99, "enrich_ip", {"ip": "203.0.113.50"})])


class BrokenClient:
    """Simulates a provider outage."""
    def __init__(self):
        self.chat = NS(completions=NS(create=self._create))

    def _create(self, **kw):
        raise RuntimeError("provider unavailable")


GOOD = dict(title="SSH brute force then compromise", severity="P1", verdict="true_positive",
            confidence="high", summary="25 failures then a success from 203.0.113.50.",
            evidence=["25 failed logins in 3 minutes", "success for admin"], mitre=["T1110", "T1078"],
            recommended_actions=["Block 203.0.113.50 after verification", "Reset the admin password"],
            reasoning="Burst followed by success from a listed IP.")


def good_script():
    return [reply([call(1, "enrich_ip", {"ip": "203.0.113.50"}), call(2, "query_events", {"src_ip": "203.0.113.50", "limit": 5})]),
            reply([call(3, "finalize_incident", GOOD)])]
