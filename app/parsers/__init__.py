"""Parsers: raw log text -> list[Event].

Each parser returns (events, errors). `errors` is a list of (line_number, line)
for lines that could not be parsed. Nothing is dropped silently.
"""
import re
from datetime import datetime, timezone
from typing import List, Tuple

from app.schemas import Event

Result = Tuple[List[Event], List[Tuple[int, str]]]

SYSLOG = re.compile(r"^(\w{3})\s+(\d{1,2}) (\d{2}:\d{2}:\d{2}) (\S+) (.*)$")
SSH_FAIL = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)")
SSH_OK = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)")
WEB = re.compile(
    r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) (\S+) "([^"]*)" "([^"]*)"'
)
FW = re.compile(r"\[UFW (BLOCK|ALLOW)\].*?SRC=(\S+) DST=(\S+).*?DPT=(\d+)")


def _syslog_ts(m, year: int) -> datetime:
    return datetime.strptime(f"{year} {m.group(1)} {m.group(2)} {m.group(3)}", "%Y %b %d %H:%M:%S")


def parse_auth(text: str, year: int = 2026) -> Result:
    events, errors = [], []
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        m = SYSLOG.match(line)
        if not m:
            errors.append((n, line)); continue
        body = m.group(5)
        f, ok = SSH_FAIL.search(body), SSH_OK.search(body)
        if f:
            action, user, ip = "login_failed", f.group(1), f.group(2)
        elif ok:
            action, user, ip = "login_success", ok.group(1), ok.group(2)
        else:
            errors.append((n, line)); continue
        events.append(Event(ts=_syslog_ts(m, year), source_type="auth", host=m.group(4),
                            src_ip=ip, user=user, action=action, message=body, raw=line))
    return events, errors


def parse_web(text: str, year: int = 2026) -> Result:
    events, errors = [], []
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        m = WEB.match(line)
        if not m:
            errors.append((n, line)); continue
        try:
            ts = datetime.strptime(m.group(2), "%d/%b/%Y:%H:%M:%S %z")
            ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
        except ValueError:
            errors.append((n, line)); continue
        events.append(Event(ts=ts, source_type="web", src_ip=m.group(1), action="http_request",
                            status=m.group(5), message=f"{m.group(3)} {m.group(4)}", raw=line))
    return events, errors


def parse_fw(text: str, year: int = 2026) -> Result:
    events, errors = [], []
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        m = SYSLOG.match(line)
        f = FW.search(line)
        if not (m and f):
            errors.append((n, line)); continue
        verdict = f.group(1)
        events.append(Event(ts=_syslog_ts(m, year), source_type="firewall", host=m.group(4),
                            src_ip=f.group(2), dst_ip=f.group(3), dst_port=int(f.group(4)),
                            action="fw_block" if verdict == "BLOCK" else "fw_allow",
                            status=verdict, message=m.group(5), raw=line))
    return events, errors


PARSERS = {"auth": parse_auth, "web": parse_web, "firewall": parse_fw}


def parse_text(text: str, source_type: str, year: int = 2026) -> Result:
    if source_type not in PARSERS:
        raise ValueError(f"unknown source_type: {source_type}")
    return PARSERS[source_type](text, year)
