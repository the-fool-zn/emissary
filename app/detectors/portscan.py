from collections import defaultdict
from datetime import timedelta
from typing import List

from app import config
from app.enrich.ip import enrich_ip, is_internal
from app.enrich.mitre import techniques
from app.schemas import Alert, Event
from .severity import Scorer


def detect_portscan(events: List[Event]) -> List[Alert]:
    win = timedelta(seconds=config.SCAN_WINDOW_SEC)
    by_ip = defaultdict(list)
    for e in sorted(events, key=lambda x: x.ts):
        if e.source_type == "firewall" and e.src_ip and e.dst_port is not None:
            by_ip[e.src_ip].append(e)

    alerts = []
    for ip, ev in by_ip.items():
        counts, j, b_start, b_end = {}, 0, None, None
        for i, e in enumerate(ev):
            counts[e.dst_port] = counts.get(e.dst_port, 0) + 1
            while e.ts - ev[j].ts > win:
                p = ev[j].dst_port
                counts[p] -= 1
                if counts[p] == 0:
                    del counts[p]
                j += 1
            if len(counts) >= config.SCAN_PORTS:
                if b_start is None:
                    b_start = ev[j].ts
                b_end = e.ts
        if b_start is None:
            continue
        seg = [e for e in ev if b_start <= e.ts <= b_end]
        ports = sorted({e.dst_port for e in seg})
        allowed = sorted({e.dst_port for e in seg if e.action == "fw_allow"})
        rep = enrich_ip(ip)
        internal = is_internal(ip)

        sc = Scorer(25, f"{len(ports)} distinct ports probed within the detection window")
        if len(ports) >= 25:
            sc.add(10, "25 or more distinct ports (broad scan)")
        if allowed:
            sc.add(15, f"probe reached open/allowed ports: {allowed[:8]}")
        if rep.get("bad_reputation"):
            sc.add(15, "source IP has bad reputation")
        if internal:
            sc.add(-5, "source IP is internal")

        alerts.append(Alert(
            detector="portscan", title=f"Port scan from {ip} against {seg[0].dst_ip}",
            src_ip=ip, first_seen=b_start, last_seen=b_end, count=len(seg),
            severity=sc.level, score=sc.score, score_reasons=sc.reasons,
            mitre=techniques("T1046" if internal else "T1595"),
            details={"distinct_ports": len(ports), "ports_sample": ports[:20],
                     "allowed_ports": allowed, "target": seg[0].dst_ip, "reputation": rep},
            evidence=[e.raw for e in seg[:10]]))
    return alerts
