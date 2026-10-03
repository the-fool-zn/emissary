"""Admin web app: login, upload + analyse, incident review, audit. One admin account, fail-closed."""
import hmac
import os
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Optional

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import config, db
from app.auth import LOGIN_COOKIE, SESSION_COOKIE, RateLimiter, Sessions, verify_password
from app.parsers import PARSERS
from app.pipeline import analyze_text
from app.reports import incident_markdown

BASE = Path(__file__).resolve().parent
SOURCE_TYPES = {"auth": "Authentication log (SSH)", "web": "Web server access log",
                "firewall": "Firewall log (UFW)"}
ALLOWED_EXT = (".log", ".txt")
MAX_PASTE_CHARS = 500_000


@dataclass
class Settings:
    admin_user: str = ""
    admin_password_hash: str = ""
    session_secret: str = ""
    session_hours: int = 8
    trust_proxy: bool = False          # set TRUST_PROXY=1 only when running behind Caddy/Nginx

    @classmethod
    def from_env(cls) -> "Settings":
        e = os.environ
        return cls(admin_user=e.get("ADMIN_USER", ""), admin_password_hash=e.get("ADMIN_PASSWORD_HASH", ""),
                   session_secret=e.get("SESSION_SECRET", ""), trust_proxy=e.get("TRUST_PROXY", "0") == "1")

    def validate(self):
        problems = []
        if not self.admin_user:
            problems.append("ADMIN_USER is not set")
        if not self.admin_password_hash.startswith("pbkdf2:sha256:"):
            problems.append("ADMIN_PASSWORD_HASH is missing or malformed (run: python make_hash.py)")
        if len(self.session_secret) < 32:
            problems.append("SESSION_SECRET must be at least 32 characters (run: python make_hash.py)")
        if problems:
            raise RuntimeError("Refusing to start: " + "; ".join(problems))


class NotAuthenticated(Exception):
    pass


def create_app(settings: Optional[Settings] = None, db_path=None, client_factory=None) -> FastAPI:
    settings = settings or Settings.from_env()
    settings.validate()
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)       # no public API docs
    app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")
    templates = Jinja2Templates(directory=str(BASE / "templates"))        # autoescape is on
    sessions = Sessions(settings.session_secret, settings.session_hours * 3600)
    ip_limiter, global_limiter = RateLimiter(5, 600), RateLimiter(60, 600)
    app.state.analysis_lock = Lock()
    app.state.client_factory = client_factory or (lambda: None)           # None -> real OpenRouter client

    # ---------- helpers ----------
    def client_ip(request: Request) -> str:
        if settings.trust_proxy:
            first = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            if first:
                return first
        return request.client.host if request.client else "unknown"

    def is_https(request: Request) -> bool:
        if request.url.scheme == "https":
            return True
        return settings.trust_proxy and request.headers.get("x-forwarded-proto") == "https"

    def get_conn():
        conn = db.connect(db_path)
        try:
            yield conn
        finally:
            conn.close()

    def require_admin(request: Request) -> dict:
        sess = sessions.read(request.cookies.get(SESSION_COOKIE))
        if not sess:
            raise NotAuthenticated()
        return sess

    def check_csrf(sess: dict, token: str):
        if not hmac.compare_digest(sess["csrf"], token or ""):
            raise HTTPException(403, "Invalid or missing CSRF token")

    def render(request: Request, name: str, sess: Optional[dict] = None, status: int = 200, **ctx):
        base = {"user": sess["u"] if sess else None, "csrf": sess["csrf"] if sess else "",
                "source_types": SOURCE_TYPES}
        return templates.TemplateResponse(request, name, {**base, **ctx}, status_code=status)

    def login_page(request: Request, status: int = 200, error: Optional[str] = None):
        token, cookie = sessions.new_login_token()
        resp = render(request, "login.html", None, status, login_token=token, error=error)
        resp.set_cookie(LOGIN_COOKIE, cookie, max_age=600, httponly=True, samesite="lax",
                        secure=is_https(request))
        return resp

    # ---------- middleware and error handling ----------
    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = ("default-src 'self'; img-src 'self' data:; "
                                                   "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        if not request.url.path.startswith("/static"):
            resp.headers["Cache-Control"] = "no-store"
        if is_https(request):
            resp.headers["Strict-Transport-Security"] = "max-age=31536000"
        return resp

    @app.exception_handler(NotAuthenticated)
    async def _not_authenticated(request: Request, exc: NotAuthenticated):
        return RedirectResponse("/login", status_code=303)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException):
        return PlainTextResponse(f"{exc.status_code}: {exc.detail}", status_code=exc.status_code)

    # ---------- public routes ----------
    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/login")
    def login_get(request: Request):
        if sessions.read(request.cookies.get(SESSION_COOKIE)):
            return RedirectResponse("/", status_code=303)
        return login_page(request)

    @app.post("/login")
    def login_post(request: Request, username: str = Form(""), password: str = Form(""),
                   csrf: str = Form(""), conn=Depends(get_conn)):
        ip = client_ip(request)
        if not sessions.check_login_token(request.cookies.get(LOGIN_COOKIE), csrf):
            return login_page(request, 403, "The page expired. Please try again.")
        if ip_limiter.blocked(ip) or global_limiter.blocked("all"):
            db.log_auth_event(conn, ip, username, "blocked")
            return login_page(request, 429, "Too many failed attempts. Try again in a few minutes.")
        pw_ok = verify_password(password[:256], settings.admin_password_hash)     # always runs: constant work
        user_ok = hmac.compare_digest(username.encode(), settings.admin_user.encode())
        if not (pw_ok and user_ok):
            ip_limiter.hit(ip)
            global_limiter.hit("all")
            db.log_auth_event(conn, ip, username, "failed")
            return login_page(request, 401, "Wrong username or password.")
        ip_limiter.reset(ip)
        db.log_auth_event(conn, ip, username, "success")
        cookie, _ = sessions.create(settings.admin_user)
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie(SESSION_COOKIE, cookie, max_age=settings.session_hours * 3600, httponly=True,
                        samesite="lax", secure=is_https(request), path="/")
        resp.delete_cookie(LOGIN_COOKIE)
        return resp

    @app.post("/logout")
    def logout(csrf: str = Form(""), sess=Depends(require_admin)):
        check_csrf(sess, csrf)
        resp = RedirectResponse("/login", status_code=303)
        resp.delete_cookie(SESSION_COOKIE, path="/")
        return resp

    # ---------- protected routes ----------
    @app.get("/")
    def dashboard(request: Request, sess=Depends(require_admin), conn=Depends(get_conn)):
        return render(request, "dashboard.html", sess, counts=db.dashboard_counts(conn),
                      open_incidents=db.list_incidents(conn, status="open", limit=10),
                      uploads=db.list_uploads(conn, 8))

    @app.get("/upload")
    def upload_get(request: Request, sess=Depends(require_admin)):
        return render(request, "upload.html", sess, max_mb=config.MAX_UPLOAD_BYTES // 1_000_000,
                      max_alerts=config.MAX_ALERTS_PER_RUN)

    @app.post("/upload")
    def upload_post(request: Request, source_type: str = Form(""), csrf: str = Form(""),
                    text: str = Form(""), file: Optional[UploadFile] = File(None),
                    sess=Depends(require_admin), conn=Depends(get_conn)):
        check_csrf(sess, csrf)
        if source_type not in SOURCE_TYPES:
            raise HTTPException(400, "Choose a valid log type")
        if file is not None and file.filename:
            name = Path(file.filename).name[:80]
            if not name.lower().endswith(ALLOWED_EXT):
                raise HTTPException(400, "Only .log and .txt files are accepted")
            data = file.file.read(config.MAX_UPLOAD_BYTES + 1)
            if len(data) > config.MAX_UPLOAD_BYTES:
                raise HTTPException(413, "File is too large")
            content = data.decode("utf-8", errors="replace")
        elif text.strip():
            if len(text) > MAX_PASTE_CHARS:
                raise HTTPException(413, "Pasted text is too large")
            name, content = "pasted.log", text
        else:
            raise HTTPException(400, "Upload a file or paste some log lines")
        if not content.strip():
            raise HTTPException(400, "The file is empty")

        lock = app.state.analysis_lock
        if not lock.acquire(blocking=False):                 # one analysis at a time: protects cost and CPU
            raise HTTPException(429, "Another analysis is running. Wait for it to finish and try again.")
        try:
            result = analyze_text(conn, name, source_type, content, client=app.state.client_factory())
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        finally:
            lock.release()
        return RedirectResponse(f"/uploads/{result['upload_id']}", status_code=303)

    @app.get("/uploads/{upload_id}")
    def upload_detail(upload_id: int, request: Request, sess=Depends(require_admin), conn=Depends(get_conn)):
        up = db.get_upload(conn, upload_id)
        if not up:
            raise HTTPException(404, "Not found")
        suggest = None
        if up["event_count"] == 0 and up["parse_errors"] > 0:        # wrong log type? find the right one
            content = db.get_upload_content(conn, upload_id) or ""
            best = max(((len(PARSERS[t](content)[0]), t) for t in PARSERS if t != up["source_type"]),
                       default=(0, None))
            suggest = best[1] if best[0] > 0 else None
        return render(request, "upload_detail.html", sess, up=up, suggest=suggest)

    @app.get("/incidents")
    def incidents(request: Request, status: str = "", severity: str = "", sess=Depends(require_admin),
                  conn=Depends(get_conn)):
        status = status if status in db.STATUSES else ""
        severity = severity if severity in ("P1", "P2", "P3", "P4") else ""
        rows = db.list_incidents(conn, status=status or None, severity=severity or None)
        return render(request, "incidents.html", sess, rows=rows, f_status=status, f_severity=severity,
                      statuses=db.STATUSES)

    @app.get("/incidents/{incident_id}")
    def incident_detail(incident_id: int, request: Request, sess=Depends(require_admin), conn=Depends(get_conn)):
        d = db.get_incident(conn, incident_id)
        if not d:
            raise HTTPException(404, "Not found")
        return render(request, "incident.html", sess, d=d, statuses=db.STATUSES)

    @app.post("/incidents/{incident_id}/status")
    def incident_status(incident_id: int, status: str = Form(""), csrf: str = Form(""),
                        sess=Depends(require_admin), conn=Depends(get_conn)):
        check_csrf(sess, csrf)
        if not db.incident_exists(conn, incident_id):
            raise HTTPException(404, "Not found")
        try:
            db.set_status(conn, incident_id, status)
        except ValueError:
            raise HTTPException(400, "Invalid status")
        return RedirectResponse(f"/incidents/{incident_id}", status_code=303)

    @app.post("/incidents/{incident_id}/feedback")
    def incident_feedback(incident_id: int, label: str = Form(""), note: str = Form(""), csrf: str = Form(""),
                          sess=Depends(require_admin), conn=Depends(get_conn)):
        check_csrf(sess, csrf)
        if not db.incident_exists(conn, incident_id):
            raise HTTPException(404, "Not found")
        try:
            db.add_feedback(conn, incident_id, label, note)
        except ValueError:
            raise HTTPException(400, "Invalid label")
        return RedirectResponse(f"/incidents/{incident_id}", status_code=303)

    @app.get("/incidents/{incident_id}/report.md")
    def incident_report(incident_id: int, sess=Depends(require_admin), conn=Depends(get_conn)):
        d = db.get_incident(conn, incident_id)
        if not d:
            raise HTTPException(404, "Not found")
        return Response(incident_markdown(d), media_type="text/markdown; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="incident-{incident_id}.md"'})

    @app.get("/audit")
    def audit(request: Request, sess=Depends(require_admin), conn=Depends(get_conn)):
        return render(request, "audit.html", sess, tool_calls=db.list_tool_calls(conn, 100),
                      logins=db.list_auth_events(conn, 50))

    return app
