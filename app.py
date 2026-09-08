#!/usr/bin/env python3
"""
Fuzzino — FastAPI server.
Multi-user, HTTPS, CSRF, brute-force protection, SSRF guard, audit log, async Ollama relay.
"""

import json
import time
import secrets
import threading
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import uvicorn
from fastapi import FastAPI, Request, HTTPException, Depends, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware

from config import settings
from scanner import StaticScanner
from report_html import generate_html_report
from security import (
    brute_force_guard, check_ssrf, generate_csrf_token, validate_csrf,
    audit, init_audit_table, get_audit_log, ensure_tls_cert,
)
from crypto import init_encryption
import db


# ── Lifespan ──

@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    db.init_false_positives_table()
    init_audit_table()
    init_encryption(settings.secret_key)

    # Retention cleanup on startup
    deleted_scans = db.cleanup_old_scans(max_age_days=90)
    deleted_audit = db.cleanup_old_audit(max_age_days=180)
    if deleted_scans or deleted_audit:
        db.vacuum()
        print(f"  Retention: cleaned {deleted_scans} old scans, {deleted_audit} audit entries")

    # Auto-generate secret key if default
    if settings.secret_key == "change-me-in-production-use-a-random-string":
        # Write a generated one to .env so it persists
        env_path = Path(__file__).parent / ".env"
        new_key = secrets.token_hex(32)
        if env_path.exists():
            content = env_path.read_text()
            if "SECRET_KEY=change-me" in content:
                content = content.replace(
                    "SECRET_KEY=change-me-in-production-use-a-random-string",
                    f"SECRET_KEY={new_key}",
                )
                env_path.write_text(content)
        else:
            env_path.write_text(f"SECRET_KEY={new_key}\n")
        settings.secret_key = new_key
        print(f"  ⚠  Generated new SECRET_KEY (saved to .env)")

    protocol = "https" if settings.enable_tls else "http"
    print(f"\n  Fuzzino")
    print(f"  Ollama (internal): {settings.ollama_host}")
    print(f"  Model:             {settings.default_model}")
    print(f"  Web GUI:           {protocol}://localhost:{settings.server_port}")
    print(f"  Ollama relay:      {protocol}://localhost:{settings.server_port}/api/relay")
    print(f"  API docs:      {protocol}://localhost:{settings.server_port}/docs")
    print(f"  HTTPS:             {'ON' if settings.enable_tls else 'OFF'}")
    print(f"  SSRF guard:        ON")
    print(f"  Brute force guard: ON (5 attempts / 5 min → 15 min lockout)")
    print(f"  Audit log:         ON")
    print(f"")
    print(f"  Remote CLI:")
    print(f"    python cli.py https://target --ollama {protocol}://<this-ip>:{settings.server_port}/api/relay -u USER -p PASS")
    print()
    yield


app = FastAPI(title="Fuzzino", lifespan=lifespan, docs_url="/docs", redoc_url=None)
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")

active_scans: dict[int, threading.Thread] = {}
scan_lock = threading.Lock()


# ── Helpers ──

def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ── Schemas ──

class LoginRequest(BaseModel):
    username: str
    password: str

class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "user"

class ScanRequest(BaseModel):
    url: str
    model: str = ""
    ollama_host: str = ""
    proxy: str = ""
    rate_limit: float = Field(default=0.1, ge=0)

class RelayGenerateRequest(BaseModel):
    model: str
    prompt: str = ""
    system: str = ""
    stream: bool = False
    options: dict = {}
    format: str = ""

class RelayChatRequest(BaseModel):
    model: str
    messages: list = []
    stream: bool = False
    options: dict = {}
    format: str = ""


# ── Auth dependency ──

def get_user(request: Request):
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = db.get_user(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def get_admin(request: Request):
    user = get_user(request)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin required")
    return user


# ── CSRF middleware ──

@app.middleware("http")
async def csrf_middleware(request: Request, call_next):
    # CSRF check on state-changing methods for session-based auth
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        path = request.url.path

        # Skip CSRF for login/setup (no session yet) and relay (CLI uses session cookie directly)
        skip_csrf = any(path.startswith(p) for p in [
            "/api/login", "/api/setup", "/api/relay",
        ])

        if not skip_csrf and "user_id" in request.session:
            csrf_cookie = request.session.get("csrf_token", "")
            csrf_header = request.headers.get("X-CSRF-Token", "")
            if not validate_csrf(csrf_cookie, csrf_header):
                return JSONResponse({"detail": "CSRF token invalid"}, status_code=403)

    response = await call_next(request)
    return response


# ── Pages ──

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    if db.user_count() == 0:
        return templates.TemplateResponse(request=request, name="setup.html")
    if "user_id" not in request.session:
        return templates.TemplateResponse(request=request, name="login.html")
    # Ensure CSRF token exists
    if "csrf_token" not in request.session:
        request.session["csrf_token"] = generate_csrf_token()
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "username": request.session.get("username", ""),
            "csrf_token": request.session["csrf_token"],
        },
    )


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if db.user_count() == 0:
        return templates.TemplateResponse(request=request, name="setup.html")
    return templates.TemplateResponse(request=request, name="login.html")


# ── Auth API ──

@app.post("/api/setup")
async def do_setup(req: LoginRequest, request: Request):
    if db.user_count() > 0:
        raise HTTPException(400, "Already set up")
    if len(req.password) < 4:
        raise HTTPException(400, "Password too short")
    db.create_user(req.username, req.password, role="admin")
    user = db.verify_user(req.username, req.password)
    if not user:
        raise HTTPException(500, "Failed to create user")
    request.session["user_id"] = user["id"]
    request.session["username"] = user["username"]
    request.session["role"] = user["role"]
    request.session["csrf_token"] = generate_csrf_token()

    ip = get_client_ip(request)
    audit("setup", f"Admin account created: {req.username}", user["id"], req.username, ip)
    return {"ok": True, "csrf_token": request.session["csrf_token"]}


@app.post("/api/login")
async def do_login(req: LoginRequest, request: Request):
    ip = get_client_ip(request)

    # Brute force check
    locked, remaining = brute_force_guard.is_locked(ip, req.username)
    if locked:
        audit("login_blocked", f"Brute force lockout: {req.username} from {ip}",
              ip=ip, username=req.username, severity="warn")
        raise HTTPException(429, f"Too many attempts. Try again in {remaining}s.")

    user = db.verify_user(req.username, req.password)

    if not user:
        was_locked = brute_force_guard.record_attempt(ip, req.username, success=False)
        audit("login_fail", f"Failed login: {req.username} from {ip}",
              ip=ip, username=req.username, severity="warn")
        if was_locked:
            raise HTTPException(429, "Too many failed attempts. Account temporarily locked.")
        raise HTTPException(401, "Invalid credentials")

    brute_force_guard.record_attempt(ip, req.username, success=True)
    request.session["user_id"] = user["id"]
    request.session["username"] = user["username"]
    request.session["role"] = user["role"]
    request.session["csrf_token"] = generate_csrf_token()

    audit("login", f"Successful login from {ip}", user["id"], user["username"], ip)
    return {"ok": True, "username": user["username"], "role": user["role"],
            "csrf_token": request.session["csrf_token"]}


@app.post("/api/logout")
async def do_logout(request: Request):
    uid = request.session.get("user_id")
    uname = request.session.get("username", "")
    ip = get_client_ip(request)
    request.session.clear()
    audit("logout", "", uid, uname, ip)
    return {"ok": True}


# ── User management ──

@app.get("/api/users")
async def list_users(admin=Depends(get_admin)):
    return db.list_users()


@app.post("/api/users")
async def create_user(req: CreateUserRequest, request: Request, admin=Depends(get_admin)):
    if not db.create_user(req.username, req.password, req.role):
        raise HTTPException(409, "Username already exists")
    ip = get_client_ip(request)
    audit("user_create", f"Created user: {req.username} ({req.role})",
          admin["id"], admin["username"], ip)
    return {"ok": True}


@app.delete("/api/users/{uid}")
async def delete_user(uid: int, request: Request, admin=Depends(get_admin)):
    if uid == request.session["user_id"]:
        raise HTTPException(400, "Cannot delete yourself")
    target = db.get_user(uid)
    db.delete_user(uid)
    ip = get_client_ip(request)
    audit("user_delete", f"Deleted user: {target['username'] if target else uid}",
          admin["id"], admin["username"], ip)
    return {"ok": True}


# ── Audit log (admin) ──

@app.get("/api/audit")
async def api_audit_log(limit: int = 200, admin=Depends(get_admin)):
    return get_audit_log(limit=limit)


# ── Models ──

@app.get("/api/models")
async def get_models(user=Depends(get_user)):
    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(f"{settings.ollama_host}/api/tags", timeout=5)
            models = [m["name"] for m in r.json().get("models", [])]
            return {"ok": True, "models": models, "default": settings.default_model}
        except Exception as e:
            return {"ok": False, "error": str(e)}


# ── Scan API ──

@app.post("/api/scan")
async def start_scan(req: ScanRequest, request: Request, user=Depends(get_user)):
    user_id = user["id"]
    ip = get_client_ip(request)
    target = req.url.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    # SSRF check
    safe, reason = check_ssrf(target)
    if not safe:
        audit("scan_blocked", f"SSRF blocked: {target} — {reason}",
              user_id, user["username"], ip, severity="warn")
        raise HTTPException(403, f"Target blocked: {reason}")

    active = db.get_user_active_scan(user_id)
    if active:
        raise HTTPException(409, f"You already have a running scan (#{active['id']})")

    model = req.model or settings.default_model
    ollama = req.ollama_host or settings.ollama_host
    proxy = req.proxy or None
    rate_limit = req.rate_limit

    scan_id: int = db.create_scan(user_id, target, model)
    audit("scan_start", f"Scan #{scan_id}: {target} (model: {model})",
          user_id, user["username"], ip)

    def run_scan():
        try:
            scanner = StaticScanner(
                ollama_host=ollama, model=model,
                proxy=proxy, rate_limit=rate_limit,
                enable_crawl=settings.enable_crawl,
                max_crawl_pages=settings.max_crawl_pages,
                enable_renderer=settings.enable_renderer,
            )
            scanner.set_progress_callback(
                lambda stage, msg, pct: db.update_scan_progress(scan_id, pct, msg)
            )
            report = scanner.run(target)
            db.finish_scan(scan_id, report)
            audit("scan_done", f"Scan #{scan_id}: {report.get('total_findings', 0)} findings",
                  user_id, user["username"], ip)

            # Send notifications
            try:
                import asyncio
                from notify import notify_scan_complete
                notify_config = {}
                if settings.webhook_url:
                    notify_config["webhook_url"] = settings.webhook_url
                if settings.slack_url:
                    notify_config["slack_url"] = settings.slack_url
                if settings.smtp_recipient:
                    notify_config["email"] = {
                        "smtp_host": settings.smtp_host,
                        "smtp_port": settings.smtp_port,
                        "sender": settings.smtp_sender,
                        "password": settings.smtp_password,
                        "recipient": settings.smtp_recipient,
                    }
                if notify_config:
                    loop = asyncio.new_event_loop()
                    loop.run_until_complete(notify_scan_complete(report, notify_config))
                    loop.close()
            except Exception:
                pass

        except Exception as e:
            db.fail_scan(scan_id, str(e))
            audit("scan_error", f"Scan #{scan_id} failed: {e}",
                  user_id, user["username"], ip, severity="error")
        finally:
            with scan_lock:
                active_scans.pop(scan_id, None)

    thread = threading.Thread(target=run_scan, daemon=True)
    with scan_lock:
        active_scans[scan_id] = thread
    thread.start()

    return {"ok": True, "scan_id": scan_id}


@app.get("/api/scan/{scan_id}/status")
async def scan_status(scan_id: int, request: Request, user=Depends(get_user)):
    is_admin = user["role"] == "admin"
    if not db.can_access_scan(scan_id, user["id"], is_admin):
        raise HTTPException(403, "Access denied")
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return {
        "id": scan["id"], "status": scan["status"],
        "progress": scan["progress"], "message": scan["progress_msg"],
        "target_url": scan["target_url"],
    }


@app.get("/api/scan/{scan_id}/report")
async def scan_report(scan_id: int, request: Request, user=Depends(get_user)):
    is_admin = user["role"] == "admin"
    if not db.can_access_scan(scan_id, user["id"], is_admin):
        raise HTTPException(403, "Access denied")
    scan = db.get_scan_with_user(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan["status"] != "done":
        raise HTTPException(400, "Scan not finished")
    report = json.loads(scan["report_json"])
    report["username"] = scan["username"]
    report["scan_id"] = scan["id"]
    return report


@app.get("/api/scan/{scan_id}/download")
async def download_json(scan_id: int, request: Request, user=Depends(get_user)):
    is_admin = user["role"] == "admin"
    if not db.can_access_scan(scan_id, user["id"], is_admin):
        raise HTTPException(403, "Access denied")
    scan = db.get_scan(scan_id)
    if not scan or not scan["report_json"]:
        raise HTTPException(404, "No report")
    ip = get_client_ip(request)
    audit("report_download", f"JSON download: scan #{scan_id}", user["id"], user["username"], ip)
    return Response(
        content=scan["report_json"], media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.json"},
    )


@app.get("/api/scan/{scan_id}/download-html")
async def download_html(scan_id: int, request: Request, user=Depends(get_user)):
    is_admin = user["role"] == "admin"
    if not db.can_access_scan(scan_id, user["id"], is_admin):
        raise HTTPException(403, "Access denied")
    scan = db.get_scan(scan_id)
    if not scan or not scan["report_json"]:
        raise HTTPException(404, "No report")
    report = json.loads(scan["report_json"])
    html = generate_html_report(report)
    ip = get_client_ip(request)
    audit("report_download", f"HTML download: scan #{scan_id}", user["id"], user["username"], ip)
    return Response(
        content=html, media_type="text/html",
        headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}_report.html"},
    )


@app.get("/api/scans")
async def list_scans(request: Request, user=Depends(get_user)):
    is_admin = user["role"] == "admin"
    scans = db.list_scans(limit=100, user_id=user["id"], is_admin=is_admin)
    for s in scans:
        s["severity_counts"] = json.loads(s["severity_counts"]) if s["severity_counts"] else {}
    return scans


@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: int, request: Request, admin=Depends(get_admin)):
    ip = get_client_ip(request)
    audit("scan_delete", f"Deleted scan #{scan_id}", admin["id"], admin["username"], ip)
    db.delete_scan(scan_id)
    return {"ok": True}


# ── Ollama Relay ──

_relay_limits: dict[int, tuple[float, int]] = {}

def _check_relay_rate(user_id: int) -> bool:
    now = time.time()
    entry = _relay_limits.get(user_id, (0, 0))
    if now - entry[0] > 60:
        _relay_limits[user_id] = (now, 1)
        return True
    if entry[1] >= settings.relay_rate_limit:
        return False
    _relay_limits[user_id] = (entry[0], entry[1] + 1)
    return True

def _require_relay_rate(request: Request):
    user = get_user(request)
    if not _check_relay_rate(user["id"]):
        raise HTTPException(429, f"Rate limit exceeded ({settings.relay_rate_limit} req/min)")
    return user


@app.get("/api/relay/api/tags")
@app.get("/api/relay/tags")
async def relay_tags(user=Depends(get_user)):
    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(f"{settings.ollama_host}/api/tags", timeout=5)
            return Response(content=r.content, status_code=r.status_code, media_type="application/json")
        except Exception as e:
            raise HTTPException(502, f"Ollama unreachable: {e}")


@app.post("/api/relay/api/generate")
@app.post("/api/relay/generate")
async def relay_generate(req: RelayGenerateRequest, user=Depends(_require_relay_rate)):
    payload = {"model": req.model, "prompt": req.prompt, "stream": False, "options": req.options}
    if req.system:
        payload["system"] = req.system
    if req.format:
        payload["format"] = req.format

    async with httpx.AsyncClient() as client:
        try:
            r = await client.post(f"{settings.ollama_host}/api/generate", json=payload, timeout=settings.llm_timeout)
            return Response(content=r.content, status_code=r.status_code, media_type="application/json")
        except Exception as e:
            raise HTTPException(502, f"Ollama unreachable: {e}")


@app.post("/api/relay/api/chat")
@app.post("/api/relay/chat")
async def relay_chat(req: RelayChatRequest, user=Depends(_require_relay_rate)):
    payload = {"model": req.model, "messages": req.messages, "stream": False, "options": req.options}
    if req.format:
        payload["format"] = req.format

    async with httpx.AsyncClient() as client:
        try:
            r = await client.post(f"{settings.ollama_host}/api/chat", json=payload, timeout=settings.llm_timeout)
            return Response(content=r.content, status_code=r.status_code, media_type="application/json")
        except Exception as e:
            raise HTTPException(502, f"Ollama unreachable: {e}")


# ── Run ──

if __name__ == "__main__":
    run_kwargs: dict = {
        "app": "app:app",
        "host": settings.server_host,
        "port": settings.server_port,
        "log_level": "info",
    }

    if settings.enable_tls:
        cert_path, key_path = ensure_tls_cert()
        run_kwargs["ssl_certfile"] = cert_path
        run_kwargs["ssl_keyfile"] = key_path
        print(f"  TLS cert: {cert_path}")

    uvicorn.run(**run_kwargs)  # type: ignore[arg-type]


# ─────────────────────────────────────────────
# Session timeout middleware
# ─────────────────────────────────────────────

@app.middleware("http")
async def session_timeout_middleware(request: Request, call_next):
    """Invalidate sessions after inactivity timeout."""
    if "user_id" in request.session:
        last_active = request.session.get("last_active", 0)
        now = time.time()
        timeout = settings.session_timeout_minutes * 60

        if last_active and (now - last_active) > timeout:
            uid = request.session.get("user_id")
            uname = request.session.get("username", "")
            request.session.clear()
            audit("session_expired", f"Session timeout for {uname}", uid, uname)

            if request.url.path.startswith("/api/"):
                return JSONResponse(
                    {"detail": "Session expired"},
                    status_code=401,
                )

        request.session["last_active"] = now

    response = await call_next(request)
    return response


# ─────────────────────────────────────────────
# Request size limit middleware
# ─────────────────────────────────────────────

@app.middleware("http")
async def request_size_middleware(request: Request, call_next):
    """Reject oversized request bodies."""
    content_length = request.headers.get("content-length")

    if content_length:
        max_bytes = settings.max_request_body_mb * 1024 * 1024

        if int(content_length) > max_bytes:
            return JSONResponse(
                {"detail": f"Request body too large (max {settings.max_request_body_mb}MB)"},
                status_code=413,
            )

    response = await call_next(request)
    return response

app.add_middleware(SessionMiddleware, secret_key=settings.secret_key)


# ─────────────────────────────────────────────
# Password change
# ─────────────────────────────────────────────

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


@app.post("/api/users/change-password")
async def change_password(
    req: ChangePasswordRequest,
    request: Request,
    user=Depends(get_user),
):
    if len(req.new_password) < 4:
        raise HTTPException(
            status_code=400,
            detail="New password too short",
        )

    verified = db.verify_user(user["username"], req.current_password)

    if not verified:
        raise HTTPException(
            status_code=401,
            detail="Current password is incorrect",
        )

    # Update password
    from werkzeug.security import generate_password_hash

    conn = db.get_db()
    conn.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (generate_password_hash(req.new_password), user["id"]),
    )
    conn.commit()
    conn.close()

    ip = get_client_ip(request)

    audit(
        "password_change",
        f"Password changed",
        user["id"],
        user["username"],
        ip,
    )

    return {"ok": True}


# ─────────────────────────────────────────────
# Scan diff
# ─────────────────────────────────────────────

@app.get("/api/scan/{scan_id}/diff/{other_scan_id}")
async def scan_diff(
    scan_id: int,
    other_scan_id: int,
    request: Request,
    user=Depends(get_user),
):
    is_admin = user["role"] == "admin"

    if not db.can_access_scan(scan_id, user["id"], is_admin):
        raise HTTPException(status_code=403, detail="Access denied")

    if not db.can_access_scan(other_scan_id, user["id"], is_admin):
        raise HTTPException(status_code=403, detail="Access denied")

    old_scan = db.get_scan(scan_id)
    new_scan = db.get_scan(other_scan_id)

    if not old_scan or not new_scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if not old_scan["report_json"] or not new_scan["report_json"]:
        raise HTTPException(status_code=400, detail="Both scans must be complete")

    from diff import diff_scans

    old_report = json.loads(old_scan["report_json"])
    new_report = json.loads(new_scan["report_json"])

    return diff_scans(old_report, new_report)


# ─────────────────────────────────────────────
# False positive management
# ─────────────────────────────────────────────

class FalsePositiveRequest(BaseModel):
    target_pattern: str
    description: str
    evidence: str
    reason: str = ""


@app.post("/api/false-positives")
async def add_fp(
    req: FalsePositiveRequest,
    request: Request,
    user=Depends(get_user),
):
    db.add_false_positive(
        req.target_pattern,
        req.description,
        req.evidence,
        req.reason,
        user["id"],
    )

    ip = get_client_ip(request)

    audit(
        "false_positive_add",
        f"Marked FP: {req.description[:60]}",
        user["id"],
        user["username"],
        ip,
    )

    return {"ok": True}


@app.get("/api/false-positives")
async def list_fp(
    target: str = "",
    user=Depends(get_user),
):
    return db.list_false_positives(target or None)


@app.delete("/api/false-positives/{fp_id}")
async def remove_fp(
    fp_id: int,
    request: Request,
    admin=Depends(get_admin),
):
    db.remove_false_positive(fp_id)

    ip = get_client_ip(request)

    audit(
        "false_positive_remove",
        f"Removed FP #{fp_id}",
        admin["id"],
        admin["username"],
        ip,
    )

    return {"ok": True}


# ─────────────────────────────────────────────
# Notification config
# ─────────────────────────────────────────────

@app.get("/api/notification-config")
async def get_notification_config(admin=Depends(get_admin)):
    return {
        "webhook_url": bool(settings.webhook_url),
        "slack_url": bool(settings.slack_url),
        "email": bool(settings.smtp_recipient),
    }