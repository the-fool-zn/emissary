import re
from collections import defaultdict
from typing import List
from urllib.parse import unquote_plus

from app import config
from app.enrich.ip import enrich_ip, is_internal
from app.enrich.mitre import techniques
from app.schemas import Alert, Event
from .severity import Scorer

PATTERNS = {
    "sql_injection": [r"union\s+select", r"'\s*or\s*'?\d'?\s*=\s*'?\d", r"\bor\s+1\s*=\s*1",
                      r"drop\s+table", r"'\s*--", r"sleep\(\d+\)", r"information_schema"],
    "path_traversal": [r"\.\./", r"\.\.\\", r"/etc/(passwd|shadow)", r"c:\\windows"],
    "xss": [r"<script", r"onerror\s*=", r"onload\s*=", r"javascript:"],
    "command_injection": [r"[;|]\s*(cat|whoami|wget|curl|nc|bash|sh|powershell)\b", r"`[^`]+`", r"\$\([^)]+\)"],
}
COMPILED = {k: [re.compile(p, re.I) for p in v] for k, v in PATTERNS.items()}
SCANNER_UA = ("sqlmap", "nikto", "nmap", "hydra", "masscan", "dirbuster", "gobuster", "wpscan")
UA = re.compile(r'"([^"]*)"\s*$')


def _decode(text: str) -> str:
    for _ in range(2):          # attackers often double-encode
        text = unquote_plus(text)
    return text


def classify(message: str) -> List[str]:
    text = _decode(message)
    return [cat for cat, pats in COMPILED.items() if any(p.search(text) for p in pats)]


def detect_webattacks(events: List[Event]) -> List[Alert]:
    hits = defaultdict(list)
    for e in sorted(events, key=lambda x: x.ts):
        if e.source_type == "web" and e.src_ip:
            cats = classify(e.message)
            if cats:
                hits[e.src_ip].append((e, cats))

    alerts = []
    for ip, items in hits.items():
        if len(items) < config.WEB_MIN_HITS:
            continue
        cats = sorted({c for _, cs in items for c in cs})
        statuses = [e.status for e, _ in items]
        server_err = any(s and s.startswith("5") for s in statuses)
        uas = {m.group(1).lower() for e, _ in items if (m := UA.search(e.raw))}
        tools = sorted(t for t in SCANNER_UA if any(t in u for u in uas))
        rep = enrich_ip(ip)

        sc = Scorer(30, f"{len(items)} attack-pattern request(s) against the web server")
        if len(items) >= 5:
            sc.add(10, "5 or more malicious requests")
        if len(cats) >= 2:
            sc.add(10, f"multiple attack types: {', '.join(cats)}")
        if server_err:
            sc.add(10, "HTTP 5xx responses suggest payloads reached the application")
        if tools:
            sc.add(5, f"automated attack tool user-agent: {', '.join(tools)}")
        if rep.get("bad_reputation"):
            sc.add(15, "source IP has bad reputation")
        if is_internal(ip):
            sc.add(-10, "source IP is internal")

        first, last = items[0][0], items[-1][0]
        alerts.append(Alert(
            detector="webattack", title=f"Web attack attempts from {ip} ({', '.join(cats)})",
            src_ip=ip, first_seen=first.ts, last_seen=last.ts, count=len(items),
            severity=sc.level, score=sc.score, score_reasons=sc.reasons, mitre=techniques("T1190"),
            details={"categories": cats, "status_codes": sorted(set(statuses)),
                     "attack_tools": tools, "reputation": rep},
            evidence=[e.raw for e, _ in items[:10]]))
    return alerts
