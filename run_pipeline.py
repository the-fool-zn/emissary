"""Full run with storage.
    python run_pipeline.py analyze auth data/samples/auth.log
    python run_pipeline.py list
    python run_pipeline.py export 1            # writes reports/incident-1.md
"""
import argparse
import json
from pathlib import Path

from app import db
from app.pipeline import analyze_text
from app.reports import incident_markdown


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze"); a.add_argument("source_type", choices=["auth", "web", "firewall"]); a.add_argument("path")
    sub.add_parser("list")
    e = sub.add_parser("export"); e.add_argument("incident_id", type=int)
    args = p.parse_args()
    conn = db.connect()

    if args.cmd == "analyze":
        path = Path(args.path)
        res = analyze_text(conn, path.name, args.source_type, path.read_text(),
                           on_tool_call=lambda t: print(f"  round {t['round']}: {t['tool']}({json.dumps(t['arguments'])[:80]})"))
        print(json.dumps(res, indent=1))
    elif args.cmd == "list":
        for r in db.list_incidents(conn):
            flag = "  (fallback)" if r["fallback"] else ""
            print(f"#{r['id']:<4} {r['severity']}  {r['verdict']:<22} {r['status']:<15} {r['title']}{flag}")
        print(db.dashboard_counts(conn))
    else:
        d = db.get_incident(conn, args.incident_id)
        if not d:
            raise SystemExit(f"no incident {args.incident_id}")
        out = Path("reports"); out.mkdir(exist_ok=True)
        f = out / f"incident-{d['id']}.md"
        f.write_text(incident_markdown(d), encoding="utf-8")
        print("wrote", f)


if __name__ == "__main__":
    main()
