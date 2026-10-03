"""Generate safe synthetic logs. Only documentation IP ranges are used
(203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24), so no real addresses appear.
Run from the project root:  python data/samples/gen_logs.py
"""
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(7)
OUT = Path(__file__).parent
START = datetime(2026, 10, 3, 8, 0, 0)
GOOD_IPS = [f"198.51.100.{i}" for i in range(10, 30)]
USERS = ["alice", "bob", "carol", "dave"]


def sys_ts(dt):
    return f"{dt.strftime('%b')} {dt.day:2d} {dt.strftime('%H:%M:%S')}"


def web_ts(dt):
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


def auth_line(dt, kind, user, ip, invalid=False):
    pid = random.randint(1000, 9999)
    port = random.randint(30000, 60000)
    if kind == "fail":
        who = f"invalid user {user}" if invalid else user
        return f"{sys_ts(dt)} web01 sshd[{pid}]: Failed password for {who} from {ip} port {port} ssh2"
    return f"{sys_ts(dt)} web01 sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2"


def web_line(dt, ip, path, code=200, ua="Mozilla/5.0"):
    return f'{ip} - - [{web_ts(dt)}] "GET {path} HTTP/1.1" {code} {random.randint(200, 5000)} "-" "{ua}"'


def fw_line(dt, ip, dst, port, verdict):
    return (f"{sys_ts(dt)} fw01 kernel: [UFW {verdict}] IN=eth0 OUT= SRC={ip} DST={dst} "
            f"PROTO=TCP SPT={random.randint(30000, 60000)} DPT={port}")


def benign_auth(n=40):
    rows = []
    for _ in range(n):
        dt = START + timedelta(seconds=random.randint(0, 3 * 3600))
        rows.append((dt, auth_line(dt, "ok", random.choice(USERS), random.choice(GOOD_IPS))))
    for _ in range(3):  # harmless typos
        dt = START + timedelta(seconds=random.randint(0, 3 * 3600))
        rows.append((dt, auth_line(dt, "fail", random.choice(USERS), random.choice(GOOD_IPS))))
    return rows


def benign_web(n=80):
    paths = ["/", "/about", "/products", "/contact", "/static/app.css", "/login"]
    rows = []
    for _ in range(n):
        dt = START + timedelta(seconds=random.randint(0, 3 * 3600))
        rows.append((dt, web_line(dt, random.choice(GOOD_IPS), random.choice(paths))))
    return rows


def benign_fw(n=60):
    rows = []
    for _ in range(n):
        dt = START + timedelta(seconds=random.randint(0, 3 * 3600))
        rows.append((dt, fw_line(dt, random.choice(GOOD_IPS), "192.0.2.10", random.choice([80, 443]), "ALLOW")))
    for _ in range(2):
        dt = START + timedelta(seconds=random.randint(0, 3 * 3600))
        rows.append((dt, fw_line(dt, random.choice(GOOD_IPS), "192.0.2.10", 23, "BLOCK")))
    return rows


def write(name, rows):
    rows.sort(key=lambda r: r[0])
    (OUT / name).write_text("\n".join(r[1] for r in rows) + "\n")
    print(f"wrote {name}: {len(rows)} lines")


def main():
    # (a) SSH brute force: 25 failures from one IP in ~3 min, then one success
    atk = "203.0.113.50"
    rows = benign_auth(20)
    t = START + timedelta(hours=1)
    for i in range(25):
        t += timedelta(seconds=random.randint(4, 9))
        user = random.choice(["root", "admin", "ubuntu", "test", "oracle"])
        rows.append((t, auth_line(t, "fail", user, atk, invalid=user != "root")))
    t += timedelta(seconds=6)
    rows.append((t, auth_line(t, "ok", "admin", atk)))
    write("auth.log", rows)

    # (b) web attacks: SQLi, traversal, XSS, command injection from one IP
    atk = "203.0.113.60"
    payloads = [
        ("/products?id=1%27%20OR%20%271%27%3D%271", 200),
        ("/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users--", 500),
        ("/products?id=1;%20DROP%20TABLE%20users;--", 500),
        ("/download?file=../../../../etc/passwd", 404),
        ("/download?file=..%2f..%2f..%2fetc%2fshadow", 404),
        ("/search?q=%3Cscript%3Ealert(1)%3C/script%3E", 200),
        ("/search?q=%3Cimg%20src=x%20onerror=alert(1)%3E", 200),
        ("/ping?host=127.0.0.1;cat%20/etc/passwd", 500),
        ("/ping?host=8.8.8.8%7Cwhoami", 500),
        ("/login?user=admin%27--", 200),
    ]
    rows = benign_web(60)
    t = START + timedelta(hours=1, minutes=30)
    for path, code in payloads:
        t += timedelta(seconds=random.randint(2, 6))
        rows.append((t, web_line(t, atk, path, code, ua="sqlmap/1.7")))
    write("web.log", rows)

    # (c) port scan: one source, 30 sequential ports in under a minute
    atk = "203.0.113.77"
    rows = benign_fw(30)
    t = START + timedelta(hours=2)
    for port in range(1, 31):
        t += timedelta(seconds=random.randint(1, 2))
        rows.append((t, fw_line(t, atk, "192.0.2.10", port, "BLOCK")))
    write("fw.log", rows)

    # (d) benign-only set
    write("benign_auth.log", benign_auth(40))
    write("benign_web.log", benign_web(80))
    write("benign_fw.log", benign_fw(60))


if __name__ == "__main__":
    main()
