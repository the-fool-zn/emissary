"""Investigate the top alert of a log file with the LLM agent.
Usage (project root, venv active):
    python run_agent.py                                  # auth.log sample
    python run_agent.py web data/samples/web.log
    python run_agent.py firewall data/samples/fw.log
    python run_agent.py auth data/samples/fp_auth.log
"""
import json
import sys
from pathlib import Path

from app.agent.agent import analyze_alert
from app.agent.tools import CaseContext
from app.detectors import run_all
from app.parsers import parse_text


def main():
    stype, path = (sys.argv[1], sys.argv[2]) if len(sys.argv) == 3 else ("auth", "data/samples/auth.log")
    events, errors = parse_text(Path(path).read_text(), stype)
    alerts = run_all(events)
    print(f"{path}: {len(events)} events, {len(errors)} unparsed, {len(alerts)} alert(s)")
    if not alerts:
        print("No alerts, nothing to investigate.")
        return
    top = alerts[0]
    print(f"Investigating {top.id} [{top.severity}] {top.title}\n")
    run = analyze_alert(top, CaseContext(events, alerts),
                        on_tool_call=lambda t: print(f"  round {t['round']}: {t['tool']}"
                                                     f"({json.dumps(t['arguments'])[:90]})"))
    i = run.incident
    print(f"\nVERDICT : {i.verdict} (confidence {i.confidence})   SEVERITY: {i.severity}")
    print(f"TITLE   : {i.title}\nSUMMARY : {i.summary}")
    print("EVIDENCE:"); [print("  -", e) for e in i.evidence]
    print("MITRE   :", ", ".join(i.mitre) or "-")
    print("ACTIONS :"); [print(f"  {n}. {a}") for n, a in enumerate(i.recommended_actions, 1)]
    print("REASONING:", i.reasoning)
    for n in i.guardrail_notes:
        print("GUARDRAIL:", n)
    print(f"\nmodel={run.model} rounds={run.rounds} tokens={run.tokens} fallback={run.fallback}")


if __name__ == "__main__":
    main()
