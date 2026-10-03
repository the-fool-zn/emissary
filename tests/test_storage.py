import runpy
from pathlib import Path

import pytest
from helpers import BrokenClient, FakeClient, good_script

from app import db
from app.pipeline import analyze_text
from app.reports import incident_markdown

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"


@pytest.fixture(scope="session", autouse=True)
def make_samples():
    if not (SAMPLES / "auth.log").exists():
        runpy.run_path(str(SAMPLES / "gen_logs.py"), run_name="__main__")


@pytest.fixture
def dbpath(tmp_path):
    return tmp_path / "test.db"


def run_auth(conn, client):
    return analyze_text(conn, "auth.log", "auth", (SAMPLES / "auth.log").read_text(), client=client, model="fake")


def test_full_pipeline_persists_everything(dbpath):
    conn = db.connect(dbpath)
    res = run_auth(conn, FakeClient(good_script()))
    assert res["events"] == 49 and res["alerts"] == 1 and len(res["incident_ids"]) == 1
    iid = res["incident_ids"][0]
    conn.close()

    conn = db.connect(dbpath)                      # a brand-new connection: data survived
    d = db.get_incident(conn, iid)
    assert d["severity"] == "P1" and d["verdict"] == "true_positive" and d["status"] == "open"
    assert d["incident"]["mitre"] == ["T1110", "T1078"]
    assert [t["tool"] for t in d["tool_calls"]] == ["enrich_ip", "query_events", "finalize_incident"]
    assert d["alert"]["src_ip"] == "203.0.113.50"
    assert db.dashboard_counts(conn)["open_by_severity"]["P1"] == 1
    assert len(db.list_tool_calls(conn)) == 3


def test_status_feedback_and_validation(dbpath):
    conn = db.connect(dbpath)
    iid = run_auth(conn, FakeClient(good_script()))["incident_ids"][0]
    db.set_status(conn, iid, "closed")
    db.add_feedback(conn, iid, "true_positive", "confirmed by admin")
    d = db.get_incident(conn, iid)
    assert d["status"] == "closed" and d["feedback"][0]["note"] == "confirmed by admin"
    assert db.list_incidents(conn, status="open") == []
    assert len(db.list_incidents(conn, status="closed")) == 1
    with pytest.raises(ValueError):
        db.set_status(conn, iid, "deleted")
    with pytest.raises(ValueError):
        db.add_feedback(conn, iid, "maybe")


def test_report_markdown(dbpath):
    conn = db.connect(dbpath)
    iid = run_auth(conn, FakeClient(good_script()))["incident_ids"][0]
    md = incident_markdown(db.get_incident(conn, iid))
    for needle in ("# Incident #1", "**P1**", "T1110", "Brute Force", "Block 203.0.113.50", "enrich_ip",
                   "Raw log evidence", "must be verified"):
        assert needle in md


def test_llm_outage_still_stores_a_safe_incident(dbpath):
    conn = db.connect(dbpath)
    res = run_auth(conn, BrokenClient())
    d = db.get_incident(conn, res["incident_ids"][0])
    assert d["fallback"] == 1 and d["verdict"] == "needs_review" and d["severity"] == "P1"
    assert "RuntimeError" in d["incident"]["reasoning"] and "provider unavailable" not in str(d)
    assert "did not complete" in incident_markdown(d)


def test_benign_file_needs_no_llm_at_all(dbpath, monkeypatch):
    monkeypatch.setattr("app.config.OPENROUTER_API_KEY", "")     # a client would fail to build
    conn = db.connect(dbpath)
    res = analyze_text(conn, "benign_auth.log", "auth", (SAMPLES / "benign_auth.log").read_text())
    assert res["alerts"] == 0 and res["incident_ids"] == []


def test_alert_cap_and_input_limits(dbpath, monkeypatch):
    conn = db.connect(dbpath)
    res = analyze_text(conn, "auth.log", "auth", (SAMPLES / "auth.log").read_text(), client=FakeClient([]),
                       model="fake", max_alerts=0)
    assert res["alerts"] == 1 and res["incident_ids"] == [] and res["not_investigated"] == 1
    monkeypatch.setattr("app.config.MAX_UPLOAD_BYTES", 10)
    with pytest.raises(ValueError):
        analyze_text(conn, "x.log", "auth", "x" * 100)
    with pytest.raises(ValueError):
        analyze_text(conn, "x.log", "nope", "x")
