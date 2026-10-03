"""Upload -> parse -> detect -> investigate with the agent -> store. One function does the whole run."""
from typing import Callable, Optional

from app import config, db
from app.agent.agent import AgentRun, _fallback, analyze_alert, make_client
from app.agent.tools import CaseContext
from app.detectors import run_all
from app.parsers import parse_text


def _failed_run(alert, model, why) -> AgentRun:
    return AgentRun(alert_id=alert.id, model=model or config.LLM_MODEL, rounds=0, tokens=0,
                    fallback=True, trace=[], incident=_fallback(alert, why))


def analyze_text(conn, filename: str, source_type: str, text: str, client=None, model: Optional[str] = None,
                 max_alerts: Optional[int] = None,
                 on_tool_call: Optional[Callable[[dict], None]] = None) -> dict:
    if len(text.encode("utf-8", "ignore")) > config.MAX_UPLOAD_BYTES:
        raise ValueError(f"file is larger than {config.MAX_UPLOAD_BYTES} bytes")
    events, errors = parse_text(text, source_type)          # raises ValueError for an unknown type
    upload_id = db.create_upload(conn, filename, source_type, text, len(events), len(errors))
    alerts = run_all(events)
    rows = [db.add_alert(conn, upload_id, a) for a in alerts]
    ctx = CaseContext(events, alerts)
    cap = max_alerts if max_alerts is not None else config.MAX_ALERTS_PER_RUN

    incident_ids = []
    if alerts and cap > 0:
        why = None
        try:
            client = client or make_client()
        except Exception as exc:                              # e.g. API key missing
            client, why = None, f"LLM not configured ({type(exc).__name__})"
        for alert, row_id in list(zip(alerts, rows))[:cap]:
            if client is None:
                run = _failed_run(alert, model, why)
            else:
                try:
                    run = analyze_alert(alert, ctx, client=client, model=model, on_tool_call=on_tool_call)
                except Exception as exc:                      # network, auth, provider outage ...
                    run = _failed_run(alert, model, f"LLM call failed ({type(exc).__name__})")
            incident_ids.append(db.add_incident(conn, upload_id, row_id, run))
    return {"upload_id": upload_id, "events": len(events), "unparsed": len(errors),
            "alerts": len(alerts), "not_investigated": max(0, len(alerts) - len(incident_ids)),
            "incident_ids": incident_ids}
