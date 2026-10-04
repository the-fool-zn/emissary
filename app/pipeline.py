"""Upload -> parse -> detect -> correlate -> investigate -> store."""

from typing import Callable, Optional

from app import config, db
from app.agent.agent import AgentRun, _fallback, analyze_alert, make_client
from app.agent.tools import CaseContext
from app.cases import correlate_alerts
from app.detectors import run_all
from app.master import MasterRun, analyze_case
from app.parsers import parse_text


def _failed_run(alert, model, why) -> AgentRun:
    return AgentRun(
        alert_id=alert.id,
        model=model or config.LLM_MODEL,
        rounds=0,
        tokens=0,
        fallback=True,
        trace=[],
        incident=_fallback(alert, why),
    )


def _failed_master_run(case, model, why) -> MasterRun:
    from app.master import _fallback as master_fallback

    return MasterRun(
        case_id=case.id,
        model=model or config.LLM_MODEL,
        rounds=0,
        tokens=0,
        fallback=True,
        assessment=master_fallback(case, why),
        trace=[],
    )


def analyze_text(
    conn,
    filename: str,
    source_type: str,
    text: str,
    client=None,
    model: Optional[str] = None,
    max_alerts: Optional[int] = None,
    on_tool_call: Optional[Callable[[dict], None]] = None,
) -> dict:

    if len(text.encode("utf-8", "ignore")) > config.MAX_UPLOAD_BYTES:
        raise ValueError(
            f"file is larger than {config.MAX_UPLOAD_BYTES} bytes"
        )

    # 1. Parse
    events, errors = parse_text(text, source_type)

    # 2. Store upload
    upload_id = db.create_upload(
        conn,
        filename,
        source_type,
        text,
        len(events),
        len(errors),
    )

    # 3. Run deterministic detectors
    alerts = run_all(events)

    # 4. Store alerts
    rows = [
        db.add_alert(conn, upload_id, alert)
        for alert in alerts
    ]

    # 5. Existing single-alert Emissary investigation
    ctx = CaseContext(events, alerts)

    cap = (
        max_alerts
        if max_alerts is not None
        else config.MAX_ALERTS_PER_RUN
    )

    incident_ids = []

    if alerts and cap > 0:

        why = None

        try:
            client = client or make_client()

        except Exception as exc:
            client, why = None, (
                f"LLM not configured ({type(exc).__name__})"
            )

        for alert, row_id in list(zip(alerts, rows))[:cap]:

            if client is None:
                run = _failed_run(
                    alert,
                    model,
                    why,
                )

            else:
                try:
                    run = analyze_alert(
                        alert,
                        ctx,
                        client=client,
                        model=model,
                        on_tool_call=on_tool_call,
                    )

                except Exception as exc:
                    run = _failed_run(
                        alert,
                        model,
                        f"LLM call failed ({type(exc).__name__})",
                    )

            incident_ids.append(
                db.add_incident(
                    conn,
                    upload_id,
                    row_id,
                    run,
                )
            )

    # 6. M2 correlation
    cases = correlate_alerts(alerts)

    # 7. M3 Master
    master_runs = []

    if cases:

        master_client = client

        if master_client is None:
            try:
                master_client = make_client()
            except Exception:
                master_client = None

        for case in cases:

            if master_client is None:
                run = _failed_master_run(
                    case,
                    model,
                    "LLM not configured",
                )

            else:
                try:
                    run = analyze_case(
                        case,
                        events,
                        alerts,
                        client=master_client,
                        model=model,
                        on_tool_call=on_tool_call,
                    )

                except Exception as exc:
                    run = _failed_master_run(
                        case,
                        model,
                        f"LLM call failed ({type(exc).__name__})",
                    )

            master_runs.append(run)

    return {
        "upload_id": upload_id,
        "events": len(events),
        "unparsed": len(errors),
        "alerts": len(alerts),
        "cases": len(cases),
        "not_investigated": max(
            0,
            len(alerts) - len(incident_ids),
        ),
        "incident_ids": incident_ids,
        "master_cases": [
            run.case_id
            for run in master_runs
        ],
    }