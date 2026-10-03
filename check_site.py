"""Security self-check for a running Emissary site (local or live). It sends only harmless requests.
    python check_site.py http://127.0.0.1:8000
    python check_site.py https://your-service.onrender.com      (first request may take ~1 minute: cold start)
Exit code 0 = every check passed.
"""
import sys

import httpx

if len(sys.argv) != 2:
    sys.exit(__doc__)
base = sys.argv[1].rstrip("/")
local = base.startswith(("http://127.0.0.1", "http://localhost"))
https = base.startswith("https://")
results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok or not detail else f"   <- {detail}"))


try:
    c = httpx.Client(follow_redirects=False, timeout=120)
    r = c.get(base + "/healthz")
except httpx.HTTPError as exc:
    sys.exit(f"Cannot reach {base}: {type(exc).__name__}")

check("health endpoint answers", r.status_code == 200 and r.json().get("status") == "ok", r.status_code)
check("transport is HTTPS (or local test)", https or local, "this site is not served over HTTPS")
if https:
    check("HSTS header present", "strict-transport-security" in r.headers)

for path in ("/docs", "/redoc", "/openapi.json"):
    check(f"API docs hidden: {path}", c.get(base + path).status_code == 404)

for path in ("/", "/upload", "/incidents", "/incidents/1", "/audit", "/uploads/1", "/incidents/1/report.md"):
    r = c.get(base + path)
    check(f"login required: GET {path}", r.status_code == 303 and r.headers.get("location", "").endswith("/login"),
          f"status {r.status_code}")
r = c.post(base + "/upload", data={"source_type": "auth", "csrf": "x", "text": "x"})
check("login required: POST /upload", r.status_code == 303 and r.headers.get("location", "").endswith("/login"),
      f"status {r.status_code}")

r = c.get(base + "/login")
h = r.headers
check("login page loads", r.status_code == 200)
csp = h.get("content-security-policy", "")
check("Content-Security-Policy is strict", "default-src 'self'" in csp and "frame-ancestors 'none'" in csp)
check("X-Frame-Options DENY", h.get("x-frame-options") == "DENY")
check("X-Content-Type-Options nosniff", h.get("x-content-type-options") == "nosniff")
check("Referrer-Policy no-referrer", h.get("referrer-policy") == "no-referrer")
check("pages are not cached", h.get("cache-control") == "no-store")
check("page contains no scripts", "<script" not in r.text.lower())
cookies = [v.lower() for v in h.get_list("set-cookie")]
check("cookie is HttpOnly", bool(cookies) and all("httponly" in v for v in cookies))
if https:
    check("cookie is Secure", bool(cookies) and all("secure" in v for v in cookies))

r = c.post(base + "/login", data={"username": "x", "password": "x", "csrf": "forged"})
check("login rejects a forged CSRF token", r.status_code == 403, r.status_code)
r = c.get(base + "/no-such-page")
check("errors reveal no stack trace", r.status_code == 404 and "Traceback" not in r.text)
check("static files served", c.get(base + "/static/style.css").status_code == 200)

failed = results.count(False)
print(f"\n{len(results) - failed}/{len(results)} checks passed")
sys.exit(1 if failed else 0)
