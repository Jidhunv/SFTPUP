"""SFileUp - password-protected internal uploader for .zip / .rar files."""
import os
import secrets
import time
from functools import wraps
from pathlib import Path

from flask import (Flask, abort, flash, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = Path(os.environ.get("SFILEUP_UPLOAD_DIR", BASE_DIR / "uploads"))
ALLOWED_EXT = {".zip", ".rar"}
# Magic bytes: ZIP ("PK\x03\x04", empty "PK\x05\x06"), RAR4 and RAR5
MAGIC = {
    ".zip": (b"PK\x03\x04", b"PK\x05\x06"),
    ".rar": (b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00"),
}
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 15 * 60

# Hash is generated with:  python set_password.py
PASSWORD_HASH = os.environ.get("SFILEUP_PASSWORD_HASH", "")
if not PASSWORD_HASH:
    hash_file = BASE_DIR / "password.hash"
    if hash_file.exists():
        PASSWORD_HASH = hash_file.read_text().strip()
if not PASSWORD_HASH:
    raise SystemExit("No password set. Run: python set_password.py")

app = Flask(__name__)
app.secret_key = os.environ.get("SFILEUP_SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    MAX_CONTENT_LENGTH=int(os.environ.get("SFILEUP_MAX_MB", "500")) * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=os.environ.get("SFILEUP_HTTPS") == "1",
    PERMANENT_SESSION_LIFETIME=30 * 60,
)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

_failures: dict[str, tuple[int, float]] = {}  # ip -> (count, first_failure_ts)


def _locked(ip: str) -> int:
    count, ts = _failures.get(ip, (0, 0.0))
    if count >= MAX_ATTEMPTS:
        remaining = int(ts + LOCKOUT_SECONDS - time.time())
        if remaining > 0:
            return remaining
        _failures.pop(ip, None)
    return 0


def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if not session.get("auth"):
            return redirect(url_for("login"))
        return view(*a, **kw)
    return wrapped


@app.before_request
def csrf_protect():
    if request.method == "POST":
        sent = request.form.get("csrf") or request.headers.get("X-CSRF")
        if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
            abort(400, "Invalid CSRF token")


@app.context_processor
def inject_csrf():
    session.setdefault("csrf", secrets.token_hex(16))
    return {"csrf": session["csrf"]}


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    return resp


@app.route("/login", methods=["GET", "POST"])
def login():
    ip = request.remote_addr or "?"
    if request.method == "POST":
        wait = _locked(ip)
        if wait:
            flash(f"Too many attempts. Try again in {wait // 60 + 1} min.", "error")
        elif check_password_hash(PASSWORD_HASH, request.form.get("password", "")):
            _failures.pop(ip, None)
            csrf = session.get("csrf")
            session.clear()
            session["csrf"] = csrf or secrets.token_hex(16)
            session["auth"] = True
            session.permanent = True
            return redirect(url_for("upload"))
        else:
            count, ts = _failures.get(ip, (0, time.time()))
            _failures[ip] = (count + 1, ts if count else time.time())
            time.sleep(1)
            flash("Incorrect password.", "error")
    return render_template("login.html")


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        f = request.files.get("file")
        name = secure_filename(f.filename) if f and f.filename else ""
        ext = Path(name).suffix.lower()
        if not name or ext not in ALLOWED_EXT:
            flash("Only .zip and .rar files are allowed.", "error")
            return redirect(url_for("upload"))
        head = f.stream.read(8)
        f.stream.seek(0)
        if not head.startswith(MAGIC[ext]):
            flash(f"File content is not a valid {ext} archive.", "error")
            return redirect(url_for("upload"))
        dest = UPLOAD_DIR / name
        if dest.exists():
            dest = UPLOAD_DIR / f"{dest.stem}_{int(time.time())}{ext}"
        f.save(dest)
        flash(f"Uploaded {dest.name}", "ok")
        return redirect(url_for("upload"))
    files = sorted(UPLOAD_DIR.glob("*"), key=lambda p: p.stat().st_mtime, reverse=True)
    return render_template("upload.html", files=[(p.name, p.stat().st_size) for p in files if p.is_file()])


@app.errorhandler(413)
def too_large(_):
    flash("File too large.", "error")
    return redirect(url_for("upload")) if session.get("auth") else redirect(url_for("login"))


if __name__ == "__main__":
    app.run(host=os.environ.get("SFILEUP_HOST", "127.0.0.1"),
            port=int(os.environ.get("SFILEUP_PORT", "5000")))
