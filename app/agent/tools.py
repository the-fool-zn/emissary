"""Read-only tools the agent may call. Nothing here writes, deletes or contacts a host."""
from typing import List

from app.enrich.ip import enrich_ip
from app.enrich.mitre import lookup_mitre
from app.schemas import Alert, Event

MAX_EVENTS = 25


class CaseContext:
    """Everything the agent is allowed to look at for one analysis run."""

    def __init__(self, events: List[Event], alerts: List[Alert]):
        self.events = sorted(events, key=lambda e: e.ts)
        self.alerts = alerts

    def alert_by_id(self, alert_id: str):
        return next((a for a in self.alerts if a.id == alert_id), None)


def alert_dict(a: Alert, evidence_chars: int = 300) -> dict:
    d = a.model_dump(mode="json")
    d["evidence"] = [line[:evidence_chars] for line in d["evidence"]]
    return d


def _event_dict(e: Event) -> dict:
    return {"ts": e.ts.isoformat(), "source": e.source_type, "action": e.action, "src_ip": e.src_ip,
            "user": e.user, "dst_port": e.dst_port, "status": e.status, "message": e.message[:200]}


def get_alert_summary(ctx: CaseContext, alert_id: str) -> dict:
    a = ctx.alert_by_id(alert_id)
    return alert_dict(a) if a else {"error": f"no alert with id {alert_id}"}


def query_events(ctx: CaseContext, src_ip=None, user=None, action=None, source_type=None,
                 contains=None, limit=15) -> dict:
    try:
        limit = max(1, min(int(limit), MAX_EVENTS))
    except (TypeError, ValueError):
        limit = 15
    rows = [e for e in ctx.events
            if (not src_ip or e.src_ip == src_ip) and (not user or e.user == user)
            and (not action or e.action == action) and (not source_type or e.source_type == source_type)
            and (not contains or contains.lower() in e.message.lower())]
    return {"matched": len(rows), "returned": min(len(rows), limit),
            "events": [_event_dict(e) for e in rows[:limit]]}


def get_related_alerts(ctx: CaseContext, src_ip: str) -> dict:
    rel = [{"id": a.id, "title": a.title, "severity": a.severity, "count": a.count}
           for a in ctx.alerts if a.src_ip == src_ip]
    return {"src_ip": src_ip, "alerts": rel}


def lookup_mitre_tool(technique_id: str) -> dict:
    m = lookup_mitre(technique_id)
    return m.model_dump() if m else {"error": f"technique {technique_id} not in local map"}


def execute_tool(name: str, args: dict, ctx: CaseContext) -> dict:
    try:
        if name == "get_alert_summary":
            return get_alert_summary(ctx, args.get("alert_id", ""))
        if name == "query_events":
            return query_events(ctx, **{k: args.get(k) for k in
                                        ("src_ip", "user", "action", "source_type", "contains", "limit")
                                        if k in args})
        if name == "enrich_ip":
            return enrich_ip(args.get("ip", ""))
        if name == "lookup_mitre":
            return lookup_mitre_tool(args.get("technique_id", ""))
        if name == "get_related_alerts":
            return get_related_alerts(ctx, args.get("src_ip", ""))
        return {"error": f"unknown tool {name}"}
    except Exception as exc:                      # tool errors go back to the model, never crash the run
        return {"error": f"{type(exc).__name__}: {exc}"}


def _fn(name, description, props, required=()):
    return {"type": "function", "function": {
        "name": name, "description": description,
        "parameters": {"type": "object", "properties": props, "required": list(required)}}}


S = {"type": "string"}
TOOLS = [
    _fn("get_alert_summary", "Return the full detector alert (score reasons, details, evidence lines).",
        {"alert_id": S}, ["alert_id"]),
    _fn("query_events", "Search normalised log events. All filters are optional and combined with AND. "
        "Returns at most 25 events, oldest first.",
        {"src_ip": S, "user": S, "source_type": {"type": "string", "enum": ["auth", "web", "firewall"]},
         "action": {"type": "string", "enum": ["login_failed", "login_success", "http_request",
                                               "fw_block", "fw_allow"]},
         "contains": {"type": "string", "description": "case-insensitive text inside the message"},
         "limit": {"type": "integer"}}),
    _fn("enrich_ip", "Reputation and context for an IP: internal or external, blocklist, abuse score.",
        {"ip": S}, ["ip"]),
    _fn("get_related_alerts", "Other alerts raised for the same source IP.", {"src_ip": S}, ["src_ip"]),
    _fn("lookup_mitre", "Look up a MITRE ATT&CK technique id such as T1110.", {"technique_id": S},
        ["technique_id"]),
    _fn("finalize_incident", "Submit the final incident. Call exactly once, when the investigation is done.",
        {"title": S,
         "severity": {"type": "string", "enum": ["P1", "P2", "P3", "P4"]},
         "verdict": {"type": "string", "enum": ["true_positive", "likely_false_positive", "needs_review"]},
         "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
         "summary": S,
         "evidence": {"type": "array", "items": S},
         "mitre": {"type": "array", "items": S, "description": "technique ids, e.g. T1110"},
         "recommended_actions": {"type": "array", "items": S},
         "reasoning": S},
        ["title", "severity", "verdict", "confidence", "summary", "evidence", "recommended_actions",
         "reasoning"]),
]
