import json
import runpy
from pathlib import Path

import pytest
from helpers import GOOD, BrokenClient, FakeClient, call, good_script, reply

from app import db
from app.agent.agent import analyze_alert
from app.agent.tools import CaseContext
from app.detectors import run_all
from app.evaluation import (SAMPLES, EvalCase, feedback_agreement, format_markdown, load_ground_truth,
                            run_ai_eval, run_detection_eval, summarize_ai, summarize_detection)
from app.parsers import parse_text


@pytest.fixture(scope="session", autouse=True)
def make_samples():
    if not (SAMPLES / "auth.log").exists():
        runpy.run_path(str(SAMPLES / "gen_logs.py"), run_name="__main__")


@pytest.fixture(scope="module")
def cases():
    return load_ground_truth()


def one(cases, cid):
    return [c for c in cases if c.id == cid]


def script(**over):
    """A scripted model run that finalizes straight away with GOOD plus overrides."""
    return [reply([call(1, "finalize_incident", dict(GOOD, **over))])]


# ---------- ground truth ----------
def test_ground_truth_is_well_formed(cases):
    assert len(cases) == 8 and len({c.id for c in cases}) == 8
    assert sum(c.alerts == 0 for c in cases) == 3                       # three benign files
    assert all(c.verdict for c in cases if c.alerts)


def test_ground_truth_validation(tmp_path):
    p = tmp_path / "t.json"
    p.write_text(json.dumps([{"id": "a", "file": "x", "source_type": "auth", "alerts": 1}]))
    with pytest.raises(ValueError):                                      # alerts expected but no verdict
        load_ground_truth(p)
    p.write_text(json.dumps([{"id": "a", "file": "x", "source_type": "auth", "alerts": 0}] * 2))
    with pytest.raises(ValueError):                                      # duplicate ids
        load_ground_truth(p)


# ---------- detection layer ----------
def test_detection_layer_matches_ground_truth(cases):
    res = run_detection_eval(cases)
    assert all(r.passed for r in res), [(r.id, r.checks) for r in res if not r.passed]
    s = summarize_detection(res, cases)
    assert s == {"cases": 8, "passed": 8, "false_alarms": 0, "missed_attacks": 0}


def test_detection_layer_catches_regressions(cases):
    wrong = one(cases, "auth_bruteforce_compromise")[0].model_copy(update={"rule_severity": "P4"})
    r = run_detection_eval([wrong])[0]
    assert not r.passed and r.checks["rule_severity"] is False
    claims_benign = one(cases, "web_sqlmap_multivector")[0].model_copy(update={"alerts": 0})
    res = run_detection_eval([claims_benign])
    assert summarize_detection(res, [claims_benign])["false_alarms"] == 1


# ---------- AI layer (scripted model, no network) ----------
def test_ai_eval_scores_a_correct_answer(cases):
    c = one(cases, "auth_bruteforce_compromise")
    res = run_ai_eval(c, FakeClient(script(mitre=["T1110", "T1078"])), model="fake")
    r = res[0]
    assert r.verdict_ok and r.severity_ok and r.mitre_jaccard == 1.0 and not r.fallback
    s = summarize_ai(res, c)
    assert s["verdict_accuracy_pct"] == 100.0 and s["dangerous_misses"] == 0 and s["runs"] == 1


def test_dangerous_miss_is_detected(cases):
    c = one(cases, "web_sqlmap_multivector")
    res = run_ai_eval(c, FakeClient(script(verdict="likely_false_positive", severity="P3", mitre=["T1190"])), model="fake")
    assert res[0].dangerous_miss and not res[0].verdict_ok
    assert summarize_ai(res, c)["dangerous_miss_rate_pct"] == 100.0


def test_false_alarm_is_detected(cases):
    c = one(cases, "fp_forgotten_password")
    res = run_ai_eval(c, FakeClient(script(verdict="true_positive", severity="P2")), model="fake")
    assert res[0].false_alarm and summarize_ai(res, c)["false_alarm_rate_pct"] == 100.0


def test_guardrail_stops_a_p1_dismissal_and_is_counted(cases):
    c = one(cases, "auth_bruteforce_compromise")
    res = run_ai_eval(c, FakeClient(script(verdict="likely_false_positive", severity="P4")), model="fake")
    r = res[0]
    assert r.verdict == "needs_review" and not r.dangerous_miss and r.guardrail_notes == 2
    assert summarize_ai(res, c)["guardrail_interventions"] == 2


def test_provider_outage_does_not_crash_the_evaluation(cases):
    c = one(cases, "fw_portscan")
    res = run_ai_eval(c, BrokenClient(), model="fake")
    assert res[0].error == "RuntimeError" and res[0].fallback and not res[0].verdict_ok
    assert summarize_ai(res, c)["fallback_rate_pct"] == 100.0


def test_consistency_across_repeats(cases):
    c = one(cases, "auth_bruteforce_compromise")
    same = run_ai_eval(c, FakeClient(script() + script()), model="fake", repeats=2)
    assert summarize_ai(same, c)["consistency_pct"] == 100.0
    differ = run_ai_eval(c, FakeClient(script() + script(verdict="likely_false_positive")), model="fake", repeats=2)
    assert summarize_ai(differ, c)["consistency_pct"] == 0.0


def test_benign_cases_never_call_the_ai(cases):
    benign = [c for c in cases if c.alerts == 0]
    assert run_ai_eval(benign, BrokenClient(), model="fake") == []


def test_markdown_report_contains_the_numbers(cases):
    c = one(cases, "auth_bruteforce_compromise")
    det = run_detection_eval(c)
    ai = run_ai_eval(c, FakeClient(script(mitre=["T1110", "T1078"])), model="fake")
    md = format_markdown(det, summarize_detection(det, c), ai, summarize_ai(ai, c), model="fake")
    for needle in ("Detection layer", "AI layer (model: fake)", "auth_bruteforce_compromise", "verdict_accuracy_pct",
                   "dangerous_misses", "Synthetic logs"):
        assert needle in md


# ---------- analyst feedback vs the model ----------
def test_feedback_agreement(tmp_path, cases):
    conn = db.connect(tmp_path / "e.db")
    text = (SAMPLES / "auth.log").read_text()
    events, _ = parse_text(text, "auth")
    alerts = run_all(events)
    up = db.create_upload(conn, "auth.log", "auth", text, len(events), 0)
    row = db.add_alert(conn, up, alerts[0])
    run = analyze_alert(alerts[0], CaseContext(events, alerts), client=FakeClient(script()), model="fake")
    iid = db.add_incident(conn, up, row, run)                              # model said true_positive
    assert feedback_agreement(conn)["labelled"] == 0
    db.add_feedback(conn, iid, "true_positive", "confirmed")
    s = feedback_agreement(conn)
    assert s["agree"] == 1 and s["agreement_pct"] == 100.0
    db.add_feedback(conn, iid, "false_positive", "changed my mind")
    s = feedback_agreement(conn)
    assert s == {"labelled": 2, "agree": 1, "disagree": 1, "model_undecided": 0, "agreement_pct": 50.0}
