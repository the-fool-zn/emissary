import runpy
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from app.detectors import run_all
from app.detectors.webattacks import classify
from app.enrich.ioc import extract_iocs
from app.enrich.ip import enrich_ip, is_internal
from app.enrich.mitre import lookup_mitre
from app.parsers import parse_text
from app.schemas import Event

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"


@pytest.fixture(scope="session", autouse=True)
def make_samples():
    if not (SAMPLES / "auth.log").exists():
        runpy.run_path(str(SAMPLES / "gen_logs.py"), run_name="__main__")


def alerts_for(name, stype):
    events, errors = parse_text((SAMPLES / name).read_text(), stype)
    assert errors == []
    return run_all(events)


def fail_events(n, ip="203.0.113.99", gap=5):
    t0 = datetime(2026, 10, 3, 9, 0, 0)
    return [Event(ts=t0 + timedelta(seconds=i * gap), source_type="auth", src_ip=ip, user="root",
                  action="login_failed", raw=f"fail {i}") for i in range(n)]


# ---- scenarios from the roadmap test matrix ----
def test_bruteforce_then_success_is_p1():
    a = alerts_for("auth.log", "auth")
    assert len(a) == 1
    assert a[0].severity == "P1" and a[0].src_ip == "203.0.113.50"
    assert {m.id for m in a[0].mitre} == {"T1110", "T1078"}
    assert a[0].details["successful_logins"]


def test_portscan_is_p3():
    a = alerts_for("fw.log", "firewall")
    assert len(a) == 1
    assert a[0].severity == "P3" and a[0].src_ip == "203.0.113.77"
    assert a[0].details["distinct_ports"] >= 25
    assert [m.id for m in a[0].mitre] == ["T1595"]


def test_web_attacks_p2_or_p3():
    a = alerts_for("web.log", "web")
    assert len(a) == 1 and a[0].severity in ("P2", "P3") and a[0].src_ip == "203.0.113.60"
    assert set(a[0].details["categories"]) == {"sql_injection", "path_traversal", "xss", "command_injection"}
    assert "sqlmap" in a[0].details["attack_tools"]


@pytest.mark.parametrize("name,stype", [("benign_auth.log", "auth"), ("benign_web.log", "web"),
                                         ("benign_fw.log", "firewall")])
def test_benign_sets_raise_nothing(name, stype):
    assert alerts_for(name, stype) == []


# ---- boundaries and units ----
def test_bruteforce_threshold_boundary():
    assert run_all(fail_events(7)) == []
    assert len(run_all(fail_events(8))) == 1


def test_slow_failures_do_not_alert():
    assert run_all(fail_events(20, gap=120)) == []   # one failure every 2 minutes


def test_web_classifier():
    assert "sql_injection" in classify("GET /p?id=1%27%20OR%20%271%27%3D%271")
    assert "path_traversal" in classify("GET /d?f=..%2f..%2fetc%2fpasswd")
    assert "command_injection" in classify("GET /ping?host=8.8.8.8%7Cwhoami")
    assert classify("GET /products?id=3&sort=asc") == []
    assert classify("GET /about") == []


def test_enrich_ip():
    assert is_internal("10.1.2.3") and not is_internal("203.0.113.5")
    assert enrich_ip("203.0.113.50")["bad_reputation"] is True
    assert enrich_ip("203.0.113.51")["bad_reputation"] is False
    assert enrich_ip("not-an-ip")["valid"] is False


def test_mitre_and_ioc():
    assert lookup_mitre("t1110").name == "Brute Force"
    r = extract_iocs("beacon to http://evil.example.com/a from 203.0.113.9 hash " + "a" * 32)
    assert r["ips"] == ["203.0.113.9"] and r["hashes"] == ["a" * 32] and "evil.example.com" in r["domains"]
