"""Run all detectors over the sample logs and print a readable summary.
Usage (from the project root):  python run_detectors.py
        python run_detectors.py auth data/samples/auth.log
"""
import sys
from pathlib import Path

from app.detectors import run_all
from app.parsers import parse_text

SAMPLES = Path("data/samples")
DEFAULT = [("auth.log", "auth"), ("web.log", "web"), ("fw.log", "firewall"),
           ("benign_auth.log", "auth"), ("benign_web.log", "web"), ("benign_fw.log", "firewall")]


def show(path: Path, stype: str):
    events, errors = parse_text(path.read_text(), stype)
    alerts = run_all(events)
    print(f"\n=== {path.name} ({stype}): {len(events)} events, {len(errors)} unparsed, {len(alerts)} alert(s)")
    for a in alerts:
        ids = ", ".join(m.id for m in a.mitre)
        print(f"  [{a.severity}] {a.id} score={a.score}  {a.title}")
        print(f"        events={a.count}  mitre={ids}")
        for r in a.score_reasons:
            print(f"          - {r}")


if __name__ == "__main__":
    if len(sys.argv) == 3:
        show(Path(sys.argv[2]), sys.argv[1])
    else:
        for name, stype in DEFAULT:
            show(SAMPLES / name, stype)
