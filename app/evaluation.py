"""M4 evaluation harness: measure Emissary against labelled ground truth.

Two layers, so you can tell WHERE an error comes from:
  1. Detection layer (rules only): free, deterministic, no network. Run it after every code change.
  2. AI layer (needs an LLM): verdict accuracy, severity agreement, ATT&CK agreement, the most
     dangerous error (an attack dismissed as a false positive), fallbacks, tokens and consistency.
Plus feedback_agreement(): how often the model's verdicts match the analyst's own labels in the database.
"""
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional

from pydantic import BaseModel

from app.agent.agent import analyze_alert
from app.agent.tools import CaseContext
from app.detectors import run_all
from app.parsers import parse_text

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_GROUND_TRUTH = ROOT / "data" / "eval" / "ground_truth.json"
SAMPLES = ROOT / "data" / "samples"
TP, FP = "true_positive", "likely_false_positive"


class EvalCase(BaseModel):
    id: str
    file: str
    source_type: str
    alerts: int                          # how many alerts the detectors should raise
    src_ip: Optional[str] = None
    rule_severity: Optional[str] = None  # what the rules should score (detection layer)
    mitre: List[str] = []
    verdict: Optional[str] = None        # what the AI should conclude (AI layer)
    final_severity: List[str] = []       # acceptable AI severities
    notes: str = ""


class DetectionResult(BaseModel):
    id: str
    passed: bool
    checks: Dict[str, bool]
    got: dict


class AIResult(BaseModel):
    id: str
    run: int
    verdict: Optional[str] = None
    severity: Optional[str] = None
    mitre: List[str] = []
    fallback: bool = False
    rounds: int = 0
    tokens: int = 0
    error: str = ""
    guardrail_notes: int = 0
    verdict_ok: bool = False
    severity_ok: bool = False
    mitre_jaccard: float = 0.0
    dangerous_miss: bool = False         # attack called a false positive
    false_alarm: bool = False            # benign activity called a true positive


def load_ground_truth(path: Path = DEFAULT_GROUND_TRUTH) -> List[EvalCase]:
    import json
    cases = [EvalCase(**c) for c in json.loads(Path(path).read_text(encoding="utf-8"))]
    ids = [c.id for c in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate case ids in ground truth")
    for c in cases:
        if c.alerts > 0 and not c.verdict:
            raise ValueError(f"case {c.id} expects alerts, so it needs an expected verdict")
    return cases


def _load(case: EvalCase, samples_dir: Path):
    text = (Path(samples_dir) / case.file).read_text(encoding="utf-8")
    events, errors = parse_text(text, case.source_type)
    return events, errors, run_all(events)


# ---------------- layer 1: detection ----------------
def run_detection_eval(cases: List[EvalCase], samples_dir: Path = SAMPLES) -> List[DetectionResult]:
    out = []
    for c in cases:
        events, errors, alerts = _load(c, samples_dir)
        got_mitre = sorted({m.id for a in alerts for m in a.mitre})
        checks = {
            "parsed_cleanly": len(errors) == 0 and len(events) > 0,
            "alert_count": len(alerts) == c.alerts,
            "source_ip": (alerts[0].src_ip == c.src_ip) if (c.src_ip and alerts) else c.src_ip is None,
            "rule_severity": (alerts[0].severity == c.rule_severity) if (c.rule_severity and alerts)
                             else c.rule_severity is None,
            "mitre": got_mitre == sorted(c.mitre),
        }
        out.append(DetectionResult(
            id=c.id, passed=all(checks.values()), checks=checks,
            got={"events": len(events), "unparsed": len(errors), "alerts": len(alerts),
                 "severity": alerts[0].severity if alerts else None, "mitre": got_mitre}))
    return out


def summarize_detection(results: List[DetectionResult], cases: List[EvalCase]) -> dict:
    by_id = {c.id: c for c in cases}
    benign = [r for r in results if by_id[r.id].alerts == 0]
    attacks = [r for r in results if by_id[r.id].alerts > 0]
    return {
        "cases": len(results),
        "passed": sum(r.passed for r in results),
        "false_alarms": sum(r.got["alerts"] > 0 for r in benign),          # benign files that raised alerts
        "missed_attacks": sum(r.got["alerts"] == 0 for r in attacks),      # attack files that raised nothing
    }


# ---------------- layer 2: AI ----------------
def _jaccard(a, b) -> float:
    a, b = set(a), set(b)
    return 1.0 if not a and not b else len(a & b) / len(a | b)


def score_ai(case: EvalCase, run_no: int, run) -> AIResult:
    inc = run.incident
    got_mitre = sorted(inc.mitre)
    return AIResult(
        id=case.id, run=run_no, verdict=inc.verdict, severity=inc.severity, mitre=got_mitre,
        fallback=run.fallback, rounds=run.rounds, tokens=run.tokens, guardrail_notes=len(inc.guardrail_notes),
        verdict_ok=inc.verdict == case.verdict,
        severity_ok=(not case.final_severity) or inc.severity in case.final_severity,
        mitre_jaccard=round(_jaccard(got_mitre, case.mitre), 3),
        dangerous_miss=case.verdict == TP and inc.verdict == FP,
        false_alarm=case.verdict == FP and inc.verdict == TP)


def run_ai_eval(cases: List[EvalCase], client, model: Optional[str] = None, repeats: int = 1,
                samples_dir: Path = SAMPLES, delay: float = 0.0,
                on_progress: Optional[Callable[[str], None]] = None) -> List[AIResult]:
    """Investigate the top alert of every attack case. Benign cases are skipped: with no alert the AI is
    never called, so detection-layer results already cover them."""
    results = []
    for c in (c for c in cases if c.alerts > 0):
        for n in range(1, repeats + 1):
            events, _, alerts = _load(c, samples_dir)
            try:
                run = analyze_alert(alerts[0], CaseContext(events, alerts), client=client, model=model)
                results.append(score_ai(c, n, run))
            except Exception as exc:
                results.append(AIResult(id=c.id, run=n, fallback=True, error=type(exc).__name__,
                                        dangerous_miss=False, false_alarm=False))
            if on_progress:
                r = results[-1]
                on_progress(f"{c.id} run {n}: verdict={r.verdict} severity={r.severity} "
                            f"{'ERROR ' + r.error if r.error else ''}")
            if delay:
                time.sleep(delay)
    return results


def _pct(n, d):
    return round(100.0 * n / d, 1) if d else None


def summarize_ai(results: List[AIResult], cases: List[EvalCase]) -> dict:
    n = len(results)
    by_id = {c.id: c for c in cases}
    confusion: Dict[str, Dict[str, int]] = {}
    for r in results:
        confusion.setdefault(by_id[r.id].verdict, {}).setdefault(r.verdict or "error", 0)
        confusion[by_id[r.id].verdict][r.verdict or "error"] += 1
    consistent, groups = 0, 0
    for cid in {r.id for r in results}:
        runs = [r.verdict for r in results if r.id == cid]
        if len(runs) > 1:
            groups += 1
            consistent += all(v == runs[0] for v in runs)
    attacks = sum(by_id[r.id].verdict == TP for r in results)
    benignish = sum(by_id[r.id].verdict == FP for r in results)
    return {
        "runs": n,
        "verdict_accuracy_pct": _pct(sum(r.verdict_ok for r in results), n),
        "severity_agreement_pct": _pct(sum(r.severity_ok for r in results), n),
        "mitre_exact_pct": _pct(sum(r.mitre_jaccard == 1.0 for r in results), n),
        "mitre_mean_jaccard": round(sum(r.mitre_jaccard for r in results) / n, 3) if n else None,
        "dangerous_misses": sum(r.dangerous_miss for r in results),
        "dangerous_miss_rate_pct": _pct(sum(r.dangerous_miss for r in results), attacks),
        "false_alarms": sum(r.false_alarm for r in results),
        "false_alarm_rate_pct": _pct(sum(r.false_alarm for r in results), benignish),
        "fallback_rate_pct": _pct(sum(r.fallback for r in results), n),
        "guardrail_interventions": sum(r.guardrail_notes for r in results),
        "mean_tokens": round(sum(r.tokens for r in results) / n) if n else None,
        "mean_rounds": round(sum(r.rounds for r in results) / n, 1) if n else None,
        "consistency_pct": _pct(consistent, groups),
        "confusion": confusion,
    }


# ---------------- analyst feedback vs the model ----------------
def feedback_agreement(conn) -> dict:
    """Compare the model's verdicts with the analyst's own true/false-positive labels in the database."""
    from app import db
    rows = db.list_feedback(conn, limit=100000)
    agree = disagree = undecided = 0
    for r in rows:
        v, label = r["model_verdict"], r["label"]
        if v == "needs_review":
            undecided += 1
        elif (v == TP and label == "true_positive") or (v == FP and label == "false_positive"):
            agree += 1
        else:
            disagree += 1
    decided = agree + disagree
    return {"labelled": len(rows), "agree": agree, "disagree": disagree, "model_undecided": undecided,
            "agreement_pct": _pct(agree, decided)}


# ---------------- report ----------------
def format_markdown(det: List[DetectionResult], det_summary: dict, ai: Optional[List[AIResult]] = None,
                    ai_summary: Optional[dict] = None, model: str = "", stamp: str = "") -> str:
    L = [f"# Emissary evaluation {stamp}".strip(), "", "## Detection layer (rules only, no AI)", "",
         f"{det_summary['passed']}/{det_summary['cases']} cases pass. "
         f"False alarms on benign files: {det_summary['false_alarms']}. "
         f"Attack files with no alert: {det_summary['missed_attacks']}.", "",
         "| Case | Result | Failed checks | Events | Alerts | Rule severity | ATT&CK |", "|---|---|---|---|---|---|---|"]
    for r in det:
        bad = ", ".join(k for k, v in r.checks.items() if not v) or "-"
        g = r.got
        L.append(f"| {r.id} | {'PASS' if r.passed else 'FAIL'} | {bad} | {g['events']} | {g['alerts']} | "
                 f"{g['severity'] or '-'} | {', '.join(g['mitre']) or '-'} |")
    if ai is not None and ai_summary is not None:
        L += ["", f"## AI layer (model: {model or 'unknown'})", "", "| Metric | Value |", "|---|---|"]
        L += [f"| {k} | {v} |" for k, v in ai_summary.items() if k != "confusion"]
        L += ["", "Verdict confusion (expected -> got):", ""]
        L += [f"- {exp}: {got}" for exp, got in ai_summary["confusion"].items()]
        L += ["", "| Case | Run | Verdict | Severity | ATT&CK | Fallback | Rounds | Tokens | Verdict OK | Sev OK |",
              "|---|---|---|---|---|---|---|---|---|---|"]
        for r in ai:
            L.append(f"| {r.id} | {r.run} | {r.verdict or r.error} | {r.severity or '-'} | "
                     f"{', '.join(r.mitre) or '-'} | {r.fallback} | {r.rounds} | {r.tokens} | "
                     f"{r.verdict_ok} | {r.severity_ok} |")
    L += ["", "*Ground truth: data/eval/ground_truth.json. Synthetic logs: results show the system works on "
          "these cases, not how it performs on real traffic.*", ""]
    return "\n".join(L)
