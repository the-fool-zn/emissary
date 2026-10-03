from pathlib import Path
import pytest
from app.parsers import parse_auth, parse_web, parse_fw, parse_text

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"

AUTH = """Oct  3 09:00:01 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.50 port 51234 ssh2
Oct  3 09:00:09 web01 sshd[1235]: Failed password for root from 203.0.113.50 port 51240 ssh2
Oct  3 09:00:15 web01 sshd[1236]: Accepted password for admin from 203.0.113.50 port 51244 ssh2
Oct  3 09:01:00 web01 sshd[1237]: Accepted publickey for alice from 198.51.100.12 port 40000 ssh2
this is not a log line
"""

WEB = '''203.0.113.60 - - [03/Oct/2026:09:30:05 +0000] "GET /products?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1" 200 512 "-" "sqlmap/1.7"
198.51.100.12 - - [03/Oct/2026:09:30:07 +0000] "GET / HTTP/1.1" 200 2048 "-" "Mozilla/5.0"
garbage
'''

FW = """Oct  3 10:00:01 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.77 DST=192.0.2.10 PROTO=TCP SPT=40000 DPT=22
Oct  3 10:00:02 fw01 kernel: [UFW ALLOW] IN=eth0 OUT= SRC=198.51.100.12 DST=192.0.2.10 PROTO=TCP SPT=40001 DPT=443
nonsense line
"""


def test_auth():
    ev, err = parse_auth(AUTH)
    assert len(ev) == 4 and len(err) == 1 and err[0][0] == 5
    assert ev[0].action == "login_failed" and ev[0].user == "admin" and ev[0].src_ip == "203.0.113.50"
    assert ev[2].action == "login_success" and ev[2].user == "admin"
    assert ev[3].user == "alice"


def test_web():
    ev, err = parse_web(WEB)
    assert len(ev) == 2 and len(err) == 1
    assert ev[0].src_ip == "203.0.113.60" and ev[0].status == "200"
    assert "OR" in ev[0].message and ev[0].message.startswith("GET /products")
    assert ev[0].ts.year == 2026 and ev[0].ts.tzinfo is None


def test_fw():
    ev, err = parse_fw(FW)
    assert len(ev) == 2 and len(err) == 1
    assert ev[0].action == "fw_block" and ev[0].dst_port == 22 and ev[0].dst_ip == "192.0.2.10"
    assert ev[1].action == "fw_allow" and ev[1].dst_port == 443


def test_unknown_type():
    with pytest.raises(ValueError):
        parse_text("x", "nope")


@pytest.mark.parametrize("fname,stype", [
    ("auth.log", "auth"), ("web.log", "web"), ("fw.log", "firewall"),
    ("benign_auth.log", "auth"), ("benign_web.log", "web"), ("benign_fw.log", "firewall"),
])
def test_sample_files_parse_cleanly(fname, stype):
    path = SAMPLES / fname
    if not path.exists():
        pytest.skip("run: python data/samples/gen_logs.py first")
    ev, err = parse_text(path.read_text(), stype)
    assert err == [] and len(ev) > 0
