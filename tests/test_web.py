import re
import runpy
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from helpers import GOOD, BrokenClient, FakeClient, call, good_script, reply

from app import db
from app.auth import hash_password, verify_password
from app.web import Settings, create_app

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"
PW = "correct horse battery staple"
SECRET = "x" * 40


@pytest.fixture(scope="session", autouse=True)
def make_samples():
    if not (SAMPLES / "auth.log").exists():
        runpy.run_path(str(SAMPLES / "gen_logs.py"), run_name="__main__")


@pytest.fixture(scope="session")
def pwhash():
    return hash_password(PW, iterations=1000)        # low cost only for fast tests


def build(tmp_path, pwhash, script=None, trust_proxy=False, factory=None):
    s = Settings(admin_user="admin", admin_password_hash=pwhash, session_secret=SECRET, trust_proxy=trust_proxy)
    f = factory or (lambda: FakeClient(script if script is not None else good_script()))
    app = create_app(s, db_path=tmp_path / "t.db", client_factory=f)
    return TestClient(app, follow_redirects=False), tmp_path / "t.db"


def token(html):
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def login(c, password=PW, username="admin"):
    t = token(c.get("/login").text)
    return c.post("/login", data={"username": username, "password": password, "csrf": t})


def authed(tmp_path, pwhash, **kw):
    c, path = build(tmp_path, pwhash, **kw)
    assert login(c).status_code == 303
    return c, path


def page_csrf(c, url="/upload"):
    return token(c.get(url).text)


def upload(c, name="auth.log", stype="auth", data=None, csrf=None):
    body = data if data is not None else (SAMPLES / name).read_bytes()
    return c.post("/upload", data={"source_type": stype, "csrf": csrf or page_csrf(c)},
                  files={"file": (name, body, "text/plain")})


# ---------- passwords ----------
def test_password_hashing(pwhash):
    assert verify_password(PW, pwhash) and not verify_password("wrong", pwhash)
    assert not verify_password(PW, "garbage") and not verify_password(PW, "")
    assert "$" not in pwhash


# ---------- startup is fail-closed ----------
def test_refuses_to_start_without_secrets(tmp_path, pwhash):
    for bad in (Settings(), Settings("a", pwhash, "short"), Settings("a", "plaintext", SECRET), Settings("", pwhash, SECRET)):
        with pytest.raises(RuntimeError):
            create_app(bad, db_path=tmp_path / "x.db")


def test_public_surface(tmp_path, pwhash):
    c, _ = build(tmp_path, pwhash)
    assert c.get("/healthz").json() == {"status": "ok"}
    assert c.get("/docs").status_code == 404 and c.get("/openapi.json").status_code == 404
    assert c.get("/login").status_code == 200


def test_everything_else_requires_login(tmp_path, pwhash):
    c, path = build(tmp_path, pwhash)
    for url in ("/", "/upload", "/incidents", "/incidents/1", "/incidents/1/report.md", "/audit", "/uploads/1"):
        r = c.get(url)
        assert r.status_code == 303 and r.headers["location"] == "/login", url
    for url in ("/upload", "/logout", "/incidents/1/status", "/incidents/1/feedback"):
        r = c.post(url, data={"csrf": "x", "source_type": "auth", "status": "closed"})
        assert r.status_code == 303 and r.headers["location"] == "/login", url
    assert db.list_uploads(db.connect(path)) == []


# ---------- login ----------
def test_login_success_and_cookie_flags(tmp_path, pwhash):
    c, path = build(tmp_path, pwhash)
    r = login(c)
    assert r.status_code == 303 and r.headers["location"] == "/"
    cookie = r.headers["set-cookie"].lower()
    assert "emissary_session=" in cookie and "httponly" in cookie and "samesite=lax" in cookie
    assert c.get("/").status_code == 200
    assert db.list_auth_events(db.connect(path))[0]["outcome"] == "success"


def test_login_failures_are_logged_and_get_no_cookie(tmp_path, pwhash):
    c, path = build(tmp_path, pwhash)
    for pw, user in (("wrong", "admin"), (PW, "root")):
        r = login(c, pw, user)
        assert r.status_code == 401 and "emissary_session" not in r.headers.get("set-cookie", "")
    outcomes = [e["outcome"] for e in db.list_auth_events(db.connect(path))]
    assert outcomes == ["failed", "failed"]
    assert c.get("/").status_code == 303


def test_login_requires_its_csrf_token(tmp_path, pwhash):
    c, _ = build(tmp_path, pwhash)
    c.get("/login")
    r = c.post("/login", data={"username": "admin", "password": PW, "csrf": "forged"})
    assert r.status_code == 403
    c2, _ = build(tmp_path, pwhash)                       # no cookie at all
    assert c2.post("/login", data={"username": "admin", "password": PW, "csrf": "x"}).status_code == 403


def test_brute_force_lockout(tmp_path, pwhash):
    c, _ = build(tmp_path, pwhash)
    for _ in range(5):
        assert login(c, "wrong").status_code == 401
    assert login(c, "wrong").status_code == 429
    assert login(c, PW).status_code == 429               # even the right password is refused while locked


def test_forged_or_tampered_session_rejected(tmp_path, pwhash):
    c, _ = build(tmp_path, pwhash)
    c.cookies.set("emissary_session", "not-a-real-cookie")
    assert c.get("/").status_code == 303
    other, _ = build(tmp_path, pwhash)                    # cookie signed with a different secret
    from app.auth import Sessions
    forged, _ = Sessions("y" * 40, 3600).create("admin")
    other.cookies.set("emissary_session", forged)
    assert other.get("/").status_code == 303


def test_logout_needs_csrf_and_ends_session(tmp_path, pwhash):
    c, _ = authed(tmp_path, pwhash)
    assert c.post("/logout", data={"csrf": "bad"}).status_code == 403
    assert c.get("/").status_code == 200
    assert c.post("/logout", data={"csrf": page_csrf(c, "/")}).status_code == 303
    c.cookies.clear()
    assert c.get("/").status_code == 303


def test_secure_cookie_and_hsts_behind_https_proxy(tmp_path, pwhash):
    c, _ = build(tmp_path, pwhash, trust_proxy=True)
    h = {"x-forwarded-proto": "https", "x-forwarded-for": "198.51.100.9"}
    t = token(c.get("/login", headers=h).text)
    r = c.post("/login", data={"username": "admin", "password": PW, "csrf": t}, headers=h)
    assert "secure" in r.headers["set-cookie"].lower()
    assert "strict-transport-security" in c.get("/healthz", headers=h).headers


# ---------- full analysis flow ----------
def test_upload_analyse_review_flow(tmp_path, pwhash):
    c, path = authed(tmp_path, pwhash)
    r = upload(c)
    assert r.status_code == 303 and r.headers["location"] == "/uploads/1"
    page = c.get("/uploads/1").text
    assert "49 events parsed" in page and "SSH brute force then compromise" in page
    assert "SSH brute force then compromise" in c.get("/incidents").text
    detail = c.get("/incidents/1").text
    assert "Block 203.0.113.50 after verification" in detail and "T1110, T1078" in detail
    assert "Failed password for invalid user admin from 203.0.113.50" in detail     # raw evidence shown
    assert "SSH brute force" in c.get("/").text
    md = c.get("/incidents/1/report.md")
    assert md.status_code == 200 and md.text.startswith("# Incident #1") and "attachment" in md.headers["content-disposition"]
    audit = c.get("/audit").text
    assert "enrich_ip" in audit and "success" in audit

    t = page_csrf(c, "/incidents/1")
    assert c.post("/incidents/1/status", data={"status": "closed", "csrf": t}).status_code == 303
    assert c.post("/incidents/1/feedback", data={"label": "true_positive", "note": "confirmed", "csrf": t}).status_code == 303
    d = db.get_incident(db.connect(path), 1)
    assert d["status"] == "closed" and d["feedback"][0]["note"] == "confirmed"
    assert "confirmed" in c.get("/incidents/1").text
    assert "No incidents match" in c.get("/incidents?status=open").text
    assert "SSH brute force" in c.get("/incidents?severity=P1&status=closed").text


def test_benign_upload_needs_no_ai(tmp_path, pwhash):
    c, _ = authed(tmp_path, pwhash, factory=lambda: BrokenClient())
    r = upload(c, "benign_auth.log")
    assert r.status_code == 303
    assert "no suspicious patterns" in c.get(r.headers["location"]).text.lower()


def test_pasted_text_works(tmp_path, pwhash):
    c, _ = authed(tmp_path, pwhash)
    text = (SAMPLES / "auth.log").read_text()
    r = c.post("/upload", data={"source_type": "auth", "csrf": page_csrf(c), "text": text})
    assert r.status_code == 303
    assert "pasted.log" in c.get("/").text


def test_ai_outage_still_gives_a_reviewable_incident(tmp_path, pwhash):
    c, _ = authed(tmp_path, pwhash, factory=lambda: BrokenClient())
    assert upload(c).status_code == 303
    page = c.get("/incidents/1").text
    assert "did not complete" in page and "RuntimeError" in page and "provider unavailable" not in page


def test_missing_llm_key_is_handled(tmp_path, pwhash, monkeypatch):
    monkeypatch.setattr("app.config.LLM_API_KEY", "")
    c, _ = authed(tmp_path, pwhash, factory=lambda: None)
    assert upload(c).status_code == 303
    assert "LLM not configured" in c.get("/incidents/1").text


# ---------- input validation and abuse ----------
def test_upload_validation(tmp_path, pwhash):
    c, path = authed(tmp_path, pwhash)
    t = page_csrf(c)
    assert upload(c, "evil.exe", data=b"x", csrf=t).status_code == 400
    assert upload(c, "a.log", stype="nope", data=b"x", csrf=t).status_code == 400
    assert upload(c, "a.log", data=b"   \n", csrf=t).status_code == 400
    assert c.post("/upload", data={"source_type": "auth", "csrf": t}).status_code == 400
    assert upload(c, "../../etc/passwd.log", data=b"junk line\n", csrf=t).status_code == 303   # name is sanitised
    assert db.list_uploads(db.connect(path))[0]["filename"] == "passwd.log"
    assert upload(c, csrf="forged").status_code == 403


def test_upload_size_limit(tmp_path, pwhash, monkeypatch):
    monkeypatch.setattr("app.config.MAX_UPLOAD_BYTES", 100)
    c, _ = authed(tmp_path, pwhash)
    assert upload(c, "big.log", data=b"x" * 500).status_code == 413


def test_one_analysis_at_a_time(tmp_path, pwhash):
    c, _ = authed(tmp_path, pwhash)
    c.app.state.analysis_lock.acquire()
    try:
        assert upload(c).status_code == 429
    finally:
        c.app.state.analysis_lock.release()
    assert upload(c).status_code == 303


def test_status_and_feedback_validation(tmp_path, pwhash):
    c, _ = authed(tmp_path, pwhash)
    upload(c)
    t = page_csrf(c, "/incidents/1")
    assert c.post("/incidents/1/status", data={"status": "deleted", "csrf": t}).status_code == 400
    assert c.post("/incidents/1/status", data={"status": "closed", "csrf": "forged"}).status_code == 403
    assert c.post("/incidents/99/status", data={"status": "closed", "csrf": t}).status_code == 404
    assert c.post("/incidents/1/feedback", data={"label": "maybe", "csrf": t}).status_code == 400
    assert c.get("/incidents/99").status_code == 404 and c.get("/uploads/99").status_code == 404
    assert "closed" not in c.get("/incidents/1").text.split("Status:")[1][:30]


# ---------- injection / XSS ----------
def test_attacker_controlled_text_is_escaped(tmp_path, pwhash):
    evil = dict(GOOD, title="<img src=x onerror=alert(1)>", summary="<script>alert('s')</script>")
    c, _ = authed(tmp_path, pwhash, script=[reply([call(1, "finalize_incident", evil)])])
    line = ('203.0.113.60 - - [03/Oct/2026:10:00:00 +0000] "GET /x?q=<script>alert(1)</script> HTTP/1.1" '
            '200 5 "-" "sqlmap"\n')
    assert upload(c, "w.log", stype="web", data=line.encode()).status_code == 303
    for url in ("/incidents/1", "/incidents", "/", "/uploads/1"):
        html = c.get(url).text
        assert "<script>alert" not in html and "<img src=x" not in html, url
    html = c.get("/incidents/1").text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html and "&lt;img src=x onerror" in html


def test_security_headers(tmp_path, pwhash):
    c, _ = authed(tmp_path, pwhash)
    h = c.get("/").headers
    assert "default-src 'self'" in h["content-security-policy"] and "frame-ancestors 'none'" in h["content-security-policy"]
    assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY"
    assert h["cache-control"] == "no-store" and h["referrer-policy"] == "no-referrer"
    assert "script" not in c.get("/").text.lower()          # no scripts at all, so CSP can stay strict
    assert c.get("/static/style.css").status_code == 200


def test_wrong_log_type_is_not_reported_as_all_clear(tmp_path, pwhash):
    c, _ = authed(tmp_path, pwhash)
    r = upload(c, "web.log", stype="auth")                      # a web log, labelled as an SSH log
    page = c.get(r.headers["location"]).text
    assert "Nothing was checked" in page and "Web server access log" in page
    assert "no suspicious patterns" not in page.lower()


def test_partially_unreadable_file_is_flagged(tmp_path, pwhash):
    c, _ = authed(tmp_path, pwhash)
    data = (SAMPLES / "benign_auth.log").read_bytes() + b"this line is garbage\n"
    r = upload(c, "mixed.log", data=data)
    page = c.get(r.headers["location"]).text
    assert "1 line(s) could not be parsed" in page
    assert "no suspicious patterns" in page.lower()
