"""The investigation loop: model <-> read-only tools, bounded and audited."""
import json
import time
from typing import Callable, List, Optional

from pydantic import BaseModel, ValidationError

from app import config
from app.schemas import Alert, Incident
from .prompts import SYSTEM_PROMPT
from .tools import TOOLS, CaseContext, alert_dict, execute_tool

LEVELS = ["P1", "P2", "P3", "P4"]


class AgentRun(BaseModel):
    alert_id: str
    model: str
    rounds: int
    tokens: int
    fallback: bool              # True when the agent could not finish and a safe default was used
    incident: Incident
    trace: List[dict]           # every tool call: this is the audit trail (stored in Phase 4)


def make_client():
    from openai import OpenAI   # imported here so tests can run without the package
    if not config.LLM_API_KEY:
        raise RuntimeError("LLM_API_KEY (or OPENROUTER_API_KEY) is missing from .env")
    return OpenAI(base_url=config.LLM_BASE_URL, api_key=config.LLM_API_KEY,
                  timeout=60, max_retries=config.LLM_MAX_RETRIES)


def apply_guardrails(inc: Incident, alert: Alert) -> Incident:
    """Code-level limits the model cannot talk its way around (prompt-injection defence)."""
    notes = []
    base, new = LEVELS.index(alert.severity), LEVELS.index(inc.severity)
    if abs(new - base) > 1:
        clamped = LEVELS[base + (1 if new > base else -1)]
        notes.append(f"model severity {inc.severity} was more than one level from the rule-based "
                     f"{alert.severity}; clamped to {clamped}")
        inc.severity = clamped
    if alert.severity == "P1" and inc.verdict == "likely_false_positive":
        notes.append("P1 alerts cannot be dismissed automatically; verdict changed to needs_review")
        inc.verdict = "needs_review"
    inc.guardrail_notes = notes
    return inc


def _fallback(alert: Alert, why: str) -> Incident:
    return Incident(
        title=alert.title, severity=alert.severity, verdict="needs_review", confidence="low",
        summary=f"Automated investigation did not complete ({why}). Showing the rule-based alert; "
                f"a human should review it.",
        evidence=alert.evidence[:5], mitre=[m.id for m in alert.mitre],
        recommended_actions=["Review this alert manually.", "Re-run the analysis if the cause was temporary."],
        reasoning=why)


def _user_message(alert: Alert, ctx: CaseContext) -> str:
    others = [a.id for a in ctx.alerts if a.id != alert.id]
    return ("Investigate this alert.\n<alert>\n" + json.dumps(alert_dict(alert), indent=1) +
            f"\n</alert>\nOther alerts in this case: {others or 'none'}.")


def _tool_call_dict(c) -> dict:
    """Rebuild a tool call for the next request. Some providers (Google Gemini 3.x) attach opaque
    'extra_content' (a thought signature) that must be sent back unchanged or the next call is rejected."""
    d = {"id": c.id, "type": "function",
         "function": {"name": c.function.name, "arguments": c.function.arguments or "{}"}}
    extra = getattr(c, "extra_content", None)
    if extra is None:
        extra = (getattr(c, "model_extra", None) or {}).get("extra_content")
    if extra:
        d["extra_content"] = extra
    return d


def analyze_alert(alert: Alert, ctx: CaseContext, client=None, model: Optional[str] = None,
                  max_rounds: Optional[int] = None,
                  on_tool_call: Optional[Callable[[dict], None]] = None) -> AgentRun:
    client = client or make_client()
    model = model or config.LLM_MODEL
    max_rounds = max_rounds or config.AGENT_MAX_ROUNDS
    deadline = time.monotonic() + config.AGENT_TIMEOUT_SEC
    messages = [{"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _user_message(alert, ctx)}]
    trace, tokens, nudged = [], 0, False

    def done(incident, rounds, fallback=False):
        return AgentRun(alert_id=alert.id, model=model, rounds=rounds, tokens=tokens,
                        fallback=fallback, incident=incident, trace=trace)

    def stop(why, rounds):
        return done(_fallback(alert, why), rounds, fallback=True)

    def record(rnd, name, args, result):
        entry = {"round": rnd, "tool": name, "arguments": args,
                 "result": json.dumps(result, default=str)[:2000]}
        trace.append(entry)
        if on_tool_call:
            on_tool_call(entry)

    for rnd in range(1, max_rounds + 1):
        if time.monotonic() > deadline:
            return stop("time limit reached", rnd - 1)
        if tokens > config.AGENT_MAX_TOKENS:
            return stop("token limit reached", rnd - 1)
        resp = client.chat.completions.create(model=model, messages=messages, tools=TOOLS,
                                              tool_choice="auto", max_tokens=1500, temperature=0)
        tokens += getattr(getattr(resp, "usage", None), "total_tokens", 0) or 0
        msg = resp.choices[0].message
        calls = getattr(msg, "tool_calls", None) or []
        messages.append({"role": "assistant", "content": msg.content or "",
                         "tool_calls": [_tool_call_dict(c) for c in calls]} if calls else
                        {"role": "assistant", "content": msg.content or ""})
        if not calls:
            if nudged:
                return stop("model answered without calling finalize_incident", rnd)
            nudged = True
            messages.append({"role": "user", "content": "Call finalize_incident now with your conclusion."})
            continue

        for c in calls:
            name = c.function.name
            try:
                args = json.loads(c.function.arguments or "{}")
                if not isinstance(args, dict):
                    raise ValueError("arguments must be a JSON object")
            except ValueError as exc:
                args, result = {}, {"error": f"invalid arguments: {exc}"}
            else:
                if name == "finalize_incident":
                    try:
                        incident = apply_guardrails(Incident(**args), alert)
                    except ValidationError as exc:
                        result = {"error": "incident failed validation: " +
                                  "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors())}
                    else:
                        record(rnd, name, args, {"accepted": True})
                        return done(incident, rnd)
                else:
                    result = execute_tool(name, args, ctx)
            record(rnd, name, args, result)
            payload = json.dumps(result, default=str)
            if len(payload) > 6000:
                payload = payload[:6000] + "...[truncated]"
            messages.append({"role": "tool", "tool_call_id": c.id, "content": payload})

    return stop("reached the maximum number of tool rounds", max_rounds)
