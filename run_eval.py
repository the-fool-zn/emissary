"""Evaluate Emissary against data/eval/ground_truth.json.

    python run_eval.py                       # detection layer only: free, no network (use after every change)
    python run_eval.py --llm                 # also run the AI on every attack case (uses your LLM quota)
    python run_eval.py --llm --only web_sqlmap_multivector,fw_portscan --repeats 2 --delay 8
    python run_eval.py --feedback            # compare model verdicts with your own true/false-positive labels
Exit code 1 if any detection case fails.
"""
import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from app import config, db
from app.evaluation import (DEFAULT_GROUND_TRUTH, feedback_agreement, format_markdown, load_ground_truth,
                            run_ai_eval, run_detection_eval, summarize_ai, summarize_detection)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--llm", action="store_true", help="also evaluate the AI layer (costs LLM requests)")
    p.add_argument("--only", default="", help="comma-separated case ids")
    p.add_argument("--repeats", type=int, default=1, help="AI runs per case (measures consistency)")
    p.add_argument("--delay", type=float, default=0.0, help="seconds to wait between AI runs (rate limits)")
    p.add_argument("--truth", default=str(DEFAULT_GROUND_TRUTH))
    p.add_argument("--out", default="", help="write the Markdown report here")
    p.add_argument("--feedback", action="store_true", help="show model-vs-analyst agreement from the database")
    a = p.parse_args()

    cases = load_ground_truth(Path(a.truth))
    if a.only:
        wanted = {x.strip() for x in a.only.split(",") if x.strip()}
        unknown = wanted - {c.id for c in cases}
        if unknown:
            sys.exit(f"unknown case id(s): {', '.join(sorted(unknown))}")
        cases = [c for c in cases if c.id in wanted]

    det = run_detection_eval(cases)
    ds = summarize_detection(det, cases)
    ai = ai_sum = None
    if a.llm:
        from app.agent.agent import make_client
        attacks = [c for c in cases if c.alerts > 0]
        print(f"AI evaluation: {len(attacks)} cases x {a.repeats} run(s); expect roughly "
              f"{5 * len(attacks) * a.repeats} LLM requests on model {config.LLM_MODEL}.")
        ai = run_ai_eval(cases, make_client(), repeats=a.repeats, delay=a.delay,
                         on_progress=lambda m: print("  " + m))
        ai_sum = summarize_ai(ai, cases)

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    md = format_markdown(det, ds, ai, ai_sum, model=config.LLM_MODEL if a.llm else "", stamp=stamp)
    print("\n" + md)
    if a.feedback:
        print("Analyst feedback vs model:", feedback_agreement(db.connect()))
    out = Path(a.out) if a.out else (Path("reports") / f"eval-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}.md" if a.llm else None)
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(md, encoding="utf-8")
        print("report written to", out)
    return 0 if ds["passed"] == ds["cases"] else 1


if __name__ == "__main__":
    sys.exit(main())
