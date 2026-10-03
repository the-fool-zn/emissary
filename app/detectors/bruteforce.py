from collections import defaultdict
from datetime import timedelta
from typing import List

from app import config
from app.enrich.ip import enrich_ip, is_internal
from app.enrich.mitre import techniques
from app.schemas import Alert, Event
from .severity import Scorer


def detect_bruteforce(events: List[Event]) -> List[Alert]:
    win = timedelta(seconds=config.BRUTE_WINDOW_SEC)
    grace = timedelta(minutes=config.BRUTE_SUCCESS_GRACE_MIN)
    fails, wins = defaultdict(list), defaultdict(list)
    for e in sorted(events, key=lambda x: x.ts):
        if e.source_type != "auth" or not e.src_ip:
            continue
        if e.action == "login_failed":
            fails[e.src_ip].append(e)
        elif e.action == "login_success":
            wins[e.src_ip].append(e)

    alerts = []
    for ip, fl in fails.items():
        j, b_start, b_end = 0, None, None
        for i in range(len(fl)):
            while fl[i].ts - fl[j].ts > win:
                j += 1
            if i - j + 1 >= config.BRUTE_THRESHOLD:
                if b_start is None:
                    b_start = fl[j].ts
                b_end = fl[i].ts
        if b_start is None:
            continue
        burst = [f for f in fl if b_start <= f.ts <= b_end]
        succ = [s for s in wins[ip] if b_start <= s.ts <= b_end + grace]
        users = sorted({f.user for f in burst if f.user})
        rep = enrich_ip(ip)

        sc = Scorer(40, f"{len(burst)} failed logins from one IP inside the detection window")
        if len(burst) >= 20:
            sc.add(10, "20 or more failures (sustained attack)")
        if succ:
            sc.add(45, f"successful login from the same IP after the burst ({', '.join(sorted({s.user for s in succ}))})")
        if rep.get("bad_reputation"):
            sc.add(15, "source IP has bad reputation")
        if is_internal(ip):
            sc.add(-10, "source IP is internal")

        title = f"SSH brute force from {ip}" + (" followed by SUCCESSFUL login" if succ else "")
        ev = [f.raw for f in burst[:6]] + [s.raw for s in succ[:3]]
        alerts.append(Alert(
            detector="bruteforce", title=title, src_ip=ip, users=users,
            first_seen=b_start, last_seen=(succ[-1].ts if succ else b_end), count=len(burst),
            severity=sc.level, score=sc.score, score_reasons=sc.reasons,
            mitre=techniques("T1110", *(["T1078"] if succ else [])),
            details={"failed_count": len(burst), "distinct_users_tried": len(users),
                     "successful_logins": [{"user": s.user, "ts": s.ts.isoformat()} for s in succ],
                     "reputation": rep},
            evidence=ev[:10]))
    return alerts
