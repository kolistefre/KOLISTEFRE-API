"""
Apni API-key dene wali website (FastAPI + SQLite).

Kya karta hai:
- User signup / login karta hai
- Dashboard par API key banata / revoke karta hai (key sirf ek baar dikhti hai)
- Key se POST /v1/chat call karta hai -> aapka server Claude ko call karta hai
- Har user ke free tokens kat-te hain, rate limit lagti hai
"""
import hashlib
import hmac
import html
import os
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from contextlib import contextmanager

import anthropic
from dotenv import load_dotenv
from fastapi import FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware

load_dotenv()

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
SECRET_KEY = os.getenv("SECRET_KEY", "")
SITE_NAME = os.getenv("SITE_NAME", "MyAI API")
KEY_PREFIX = os.getenv("KEY_PREFIX", "sk-myai-")
FREE_TOKENS = int(os.getenv("FREE_TOKENS", "50000"))
RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", "20"))
MAX_OUTPUT_TOKENS = int(os.getenv("MAX_OUTPUT_TOKENS", "1000"))
MODEL = os.getenv("MODEL", "claude-haiku-4-5-20251001")
DB_PATH = os.getenv("DB_PATH", "app.db")
MAX_KEYS_PER_USER = 5

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY .env mein set karo (README dekho).")

app = FastAPI(title=SITE_NAME)
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    same_site="lax",
    https_only=os.getenv("HTTPS_ONLY", "0") == "1",
    max_age=7 * 24 * 3600,
)

# ---------------------------------------------------------------- database


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_db() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                tokens_left INTEGER NOT NULL,
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                prefix TEXT NOT NULL,
                key_hash TEXT UNIQUE NOT NULL,
                created_at REAL NOT NULL,
                last_used REAL,
                revoked INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                input_tokens INTEGER NOT NULL,
                output_tokens INTEGER NOT NULL,
                created_at REAL NOT NULL
            );
            """
        )


init_db()

# ---------------------------------------------------------------- security helpers


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    h = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return salt.hex() + ":" + h.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, h_hex = stored.split(":")
        h = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1)
        return hmac.compare_digest(h.hex(), h_hex)
    except Exception:
        return False


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def new_api_key() -> str:
    return KEY_PREFIX + secrets.token_urlsafe(32)


# In-memory rate limiter (ek server process ke liye theek hai)
_hits: dict[int, deque] = defaultdict(deque)


def rate_limited(key_id: int) -> bool:
    now = time.time()
    q = _hits[key_id]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= RATE_LIMIT_PER_MIN:
        return True
    q.append(now)
    return False


# ---------------------------------------------------------------- HTML helpers

CSS = """
:root{--bg:#f6f5f1;--ink:#1d2320;--muted:#66706b;--line:#d9d8d0;--card:#fff;--accent:#0f5c4d;--accent-ink:#fff;--warn:#9b2c1f;--code:#eceae2}
@media (prefers-color-scheme:dark){:root{--bg:#131715;--ink:#e9ece9;--muted:#95a09a;--line:#2a322e;--card:#1a201d;--accent:#4fc3a1;--accent-ink:#0c1a15;--warn:#ff8b7a;--code:#222a26}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
header{border-bottom:1px solid var(--line);padding:14px 20px;display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
header a{color:var(--ink);text-decoration:none;font-weight:600}
nav{display:flex;gap:16px;align-items:center}
nav a{font-weight:400;color:var(--muted)}
main{max-width:760px;margin:0 auto;padding:32px 20px 64px}
h1{font-size:1.9rem;line-height:1.2;margin:0 0 12px;letter-spacing:-.01em}
h2{font-size:1.15rem;margin:32px 0 10px}
p{margin:0 0 14px}
.muted{color:var(--muted)}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:18px;margin:0 0 16px}
label{display:block;font-size:.9rem;margin:12px 0 4px}
input{width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--ink);font:inherit}
input:focus-visible,button:focus-visible,a:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
button{padding:10px 16px;border:0;border-radius:6px;background:var(--accent);color:var(--accent-ink);font:inherit;font-weight:600;cursor:pointer;margin-top:14px}
button.plain{background:transparent;color:var(--warn);border:1px solid var(--line);margin:0;padding:6px 10px;font-weight:500}
.err{color:var(--warn);margin:0 0 12px}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.86rem}
pre{background:var(--code);padding:14px;border-radius:6px;overflow-x:auto;margin:8px 0 0}
.newkey{border-color:var(--accent);border-width:2px}
.newkey code{word-break:break-all;font-size:.95rem}
table{width:100%;border-collapse:collapse;font-size:.92rem}
th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);vertical-align:middle}
th{font-weight:600;color:var(--muted)}
.tbl{overflow-x:auto}
"""


def esc(s) -> str:
    return html.escape(str(s), quote=True)


def layout(title: str, body: str, user=None) -> HTMLResponse:
    if user:
        nav = f'<nav><a href="/dashboard">Dashboard</a><span class="muted">{esc(user["email"])}</span><a href="/logout">Logout</a></nav>'
    else:
        nav = '<nav><a href="/login">Login</a><a href="/signup">Sign up</a></nav>'
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)} | {esc(SITE_NAME)}</title><style>{CSS}</style></head>
<body><header><a href="/">{esc(SITE_NAME)}</a>{nav}</header><main>{body}</main></body></html>"""
    return HTMLResponse(page)


def current_user(request: Request):
    uid = request.session.get("uid")
    if not uid:
        return None
    with get_db() as c:
        return c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()


def fmt_time(ts):
    if not ts:
        return "never"
    return time.strftime("%d %b %Y, %H:%M", time.gmtime(ts)) + " UTC"


# ---------------------------------------------------------------- pages


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    user = current_user(request)
    cta = (
        '<a href="/dashboard"><button>Open dashboard</button></a>'
        if user
        else f'<a href="/signup"><button>Get your API key</button></a>'
    )
    body = f"""
<h1>Add AI to your app with one API key</h1>
<p class="muted">Sign up, create a key, and send messages to our endpoint. Every new account starts with {FREE_TOKENS:,} free tokens.</p>
{cta}
<h2>Example request</h2>
<pre>curl -X POST {esc(str(request.base_url).rstrip('/'))}/v1/chat \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{{"message": "Namaste! Apna intro do."}}'</pre>
"""
    return layout("Home", body, user)


@app.get("/signup", response_class=HTMLResponse)
def signup_page(request: Request, error: str = ""):
    err = f'<p class="err">{esc(error)}</p>' if error else ""
    body = f"""<h1>Create your account</h1>{err}
<form method="post" action="/signup" class="card">
<label for="email">Email</label><input id="email" name="email" type="email" required autocomplete="email">
<label for="password">Password (at least 8 characters)</label><input id="password" name="password" type="password" minlength="8" required autocomplete="new-password">
<button type="submit">Create account</button></form>
<p class="muted">Already registered? <a href="/login">Log in</a></p>"""
    return layout("Sign up", body)


@app.post("/signup")
def signup(request: Request, email: str = Form(...), password: str = Form(...)):
    email = email.strip().lower()
    if "@" not in email or len(email) > 200:
        return RedirectResponse("/signup?error=Enter+a+valid+email", status_code=303)
    if len(password) < 8 or len(password) > 200:
        return RedirectResponse("/signup?error=Password+must+be+8+to+200+characters", status_code=303)
    try:
        with get_db() as c:
            cur = c.execute(
                "INSERT INTO users (email, password_hash, tokens_left, created_at) VALUES (?,?,?,?)",
                (email, hash_password(password), FREE_TOKENS, time.time()),
            )
            uid = cur.lastrowid
    except sqlite3.IntegrityError:
        return RedirectResponse("/signup?error=This+email+is+already+registered", status_code=303)
    request.session["uid"] = uid
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, error: str = ""):
    err = f'<p class="err">{esc(error)}</p>' if error else ""
    body = f"""<h1>Log in</h1>{err}
<form method="post" action="/login" class="card">
<label for="email">Email</label><input id="email" name="email" type="email" required autocomplete="email">
<label for="password">Password</label><input id="password" name="password" type="password" required autocomplete="current-password">
<button type="submit">Log in</button></form>
<p class="muted">New here? <a href="/signup">Create an account</a></p>"""
    return layout("Log in", body)


@app.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...)):
    with get_db() as c:
        u = c.execute("SELECT * FROM users WHERE email=?", (email.strip().lower(),)).fetchone()
    if not u or not verify_password(password, u["password_hash"]):
        return RedirectResponse("/login?error=Wrong+email+or+password", status_code=303)
    request.session["uid"] = u["id"]
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=303)


def render_dashboard(request: Request, user, new_key: str = "", error: str = ""):
    with get_db() as c:
        keys = c.execute("SELECT * FROM api_keys WHERE user_id=? ORDER BY id DESC", (user["id"],)).fetchall()
        tot = c.execute(
            "SELECT COUNT(*) n, COALESCE(SUM(input_tokens),0) i, COALESCE(SUM(output_tokens),0) o FROM usage WHERE user_id=?",
            (user["id"],),
        ).fetchone()
        fresh = c.execute("SELECT tokens_left FROM users WHERE id=?", (user["id"],)).fetchone()

    banner = ""
    if new_key:
        banner = f"""<div class="card newkey"><strong>Your new API key</strong>
<p class="muted">Copy it now. For your security it is shown only once and cannot be recovered.</p>
<code>{esc(new_key)}</code></div>"""
    err = f'<p class="err">{esc(error)}</p>' if error else ""

    rows = ""
    for k in keys:
        status = "revoked" if k["revoked"] else "active"
        action = (
            ""
            if k["revoked"]
            else f'<form method="post" action="/keys/revoke/{k["id"]}"><button class="plain" type="submit">Revoke</button></form>'
        )
        rows += f"<tr><td>{esc(k['name'])}</td><td><code>{esc(k['prefix'])}…</code></td><td>{status}</td><td>{fmt_time(k['last_used'])}</td><td>{action}</td></tr>"
    if not rows:
        rows = '<tr><td colspan="5" class="muted">No keys yet. Create your first key above.</td></tr>'

    base = esc(str(request.base_url).rstrip("/"))
    body = f"""
<h1>Dashboard</h1>{err}{banner}
<div class="card">
<p><strong>{fresh['tokens_left']:,}</strong> tokens left</p>
<p class="muted">Used so far: {tot['n']:,} requests, {tot['i']:,} input tokens, {tot['o']:,} output tokens.</p>
</div>
<h2>Create an API key</h2>
<form method="post" action="/keys/create" class="card">
<label for="name">Key name</label><input id="name" name="name" maxlength="40" placeholder="My website" required>
<button type="submit">Create key</button></form>
<h2>Your keys</h2>
<div class="card tbl"><table>
<tr><th>Name</th><th>Key</th><th>Status</th><th>Last used</th><th></th></tr>{rows}</table></div>
<h2>How to use</h2>
<pre>curl -X POST {base}/v1/chat \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{{"message": "Hello!"}}'</pre>
"""
    return layout("Dashboard", body, user)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    return render_dashboard(request, user)


@app.post("/keys/create", response_class=HTMLResponse)
def create_key(request: Request, name: str = Form(...)):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    name = name.strip()[:40] or "key"
    with get_db() as c:
        active = c.execute(
            "SELECT COUNT(*) n FROM api_keys WHERE user_id=? AND revoked=0", (user["id"],)
        ).fetchone()["n"]
        if active >= MAX_KEYS_PER_USER:
            return render_dashboard(request, user, error=f"You can have at most {MAX_KEYS_PER_USER} active keys. Revoke one first.")
        key = new_api_key()
        c.execute(
            "INSERT INTO api_keys (user_id, name, prefix, key_hash, created_at) VALUES (?,?,?,?,?)",
            (user["id"], name, key[: len(KEY_PREFIX) + 6], hash_key(key), time.time()),
        )
    return render_dashboard(request, user, new_key=key)


@app.post("/keys/revoke/{key_id}")
def revoke_key(request: Request, key_id: int):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    with get_db() as c:
        c.execute("UPDATE api_keys SET revoked=1 WHERE id=? AND user_id=?", (key_id, user["id"]))
    return RedirectResponse("/dashboard", status_code=303)


# ---------------------------------------------------------------- the API


class ChatIn(BaseModel):
    message: str = Field(..., min_length=1, max_length=8000)
    system: str | None = Field(None, max_length=2000)
    max_tokens: int = Field(500, ge=1, le=4096)


def get_client():
    if not ANTHROPIC_API_KEY:
        raise HTTPException(500, "Server par ANTHROPIC_API_KEY set nahi hai.")
    return anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)


@app.post("/v1/chat")
def chat(body: ChatIn, authorization: str = Header(default="")):
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Authorization header missing. Use: Authorization: Bearer YOUR_API_KEY")
    key = authorization[7:].strip()

    with get_db() as c:
        row = c.execute(
            """SELECT k.id AS key_id, k.user_id, u.tokens_left
               FROM api_keys k JOIN users u ON u.id = k.user_id
               WHERE k.key_hash=? AND k.revoked=0""",
            (hash_key(key),),
        ).fetchone()
    if not row:
        raise HTTPException(401, "Invalid or revoked API key.")
    if rate_limited(row["key_id"]):
        raise HTTPException(429, f"Rate limit: max {RATE_LIMIT_PER_MIN} requests per minute.")
    if row["tokens_left"] <= 0:
        raise HTTPException(402, "Tokens khatam. Please add credits.")

    try:
        kwargs = dict(
            model=MODEL,
            max_tokens=min(body.max_tokens, MAX_OUTPUT_TOKENS),
            messages=[{"role": "user", "content": body.message}],
        )
        if body.system:
            kwargs["system"] = body.system
        resp = get_client().messages.create(**kwargs)
    except HTTPException:
        raise
    except anthropic.APIError:
        raise HTTPException(502, "AI service abhi available nahi hai. Thodi der baad try karo.")

    reply = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
    used_in, used_out = resp.usage.input_tokens, resp.usage.output_tokens
    now = time.time()
    with get_db() as c:
        c.execute(
            "UPDATE users SET tokens_left = MAX(0, tokens_left - ?) WHERE id=?",
            (used_in + used_out, row["user_id"]),
        )
        c.execute("UPDATE api_keys SET last_used=? WHERE id=?", (now, row["key_id"]))
        c.execute(
            "INSERT INTO usage (key_id, user_id, input_tokens, output_tokens, created_at) VALUES (?,?,?,?,?)",
            (row["key_id"], row["user_id"], used_in, used_out, now),
        )
        left = c.execute("SELECT tokens_left FROM users WHERE id=?", (row["user_id"],)).fetchone()["tokens_left"]

    return {
        "reply": reply,
        "usage": {"input_tokens": used_in, "output_tokens": used_out},
        "tokens_left": left,
    }
