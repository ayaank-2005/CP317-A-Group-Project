import argparse
import getpass
import hashlib
import html
import mimetypes
import os
import re
import secrets
import sqlite3
import time
import uuid
from contextlib import closing, contextmanager
from http.cookies import SimpleCookie, CookieError
from pathlib import Path
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server

import bcrypt

ROOT = Path(__file__).resolve().parent
DATABASE_URL = os.getenv("DATABASE_URL")
ASSETS = {"Styling.css", "database.css", "router.js", "scanner.js", "database.js"}
PORT = 8000
HOSTS = {f"localhost:{PORT}", f"127.0.0.1:{PORT}"}
PLACEHOLDER = '<main id="v-signin" class="hidden"></main>'
ACCOUNT_STYLE = """<style>
.account-form input[type="email"],
.account-form input[type="password"] {
    display: block;
    width: 100%;
    font: inherit;
    color: var(--ink);
    background: var(--bg);
    border: 1.5px solid var(--ink);
    border-radius: 10px;
    padding: 12px 14px;
    margin-bottom: 14px;
}
.account-form input:focus-visible {
    outline: 3px solid var(--accent);
    outline-offset: 2px;
}
</style>"""
COOKIE = "scamshield_session"
SESSION_SECONDS = 8 * 60 * 60
MESSAGES = {
    "invalid": "Enter a valid email and a password of at least 12 characters (up to 72 UTF-8 bytes).",
    "exists": "That account could not be created. Try signing in.",
    "failed": "The email or password is incorrect.",
    "out": "You are signed out.",
}


@contextmanager
def database():
    if DATABASE_URL:
        import psycopg2
        conn = psycopg2.connect(DATABASE_URL)
    else:
        folder = Path.home() / ".scamshield"
        folder.mkdir(mode=0o700, exist_ok=True)
        conn = sqlite3.connect(folder / "accounts.sqlite3")
        conn.execute("PRAGMA foreign_keys = ON")
    with closing(conn), conn, closing(conn.cursor()) as cursor:
        yield cursor


def execute(cursor, sql, values=()):
    cursor.execute(sql.replace("?", "%s") if DATABASE_URL else sql, values)
    return cursor


def initialize():
    with database() as cursor:
        if not DATABASE_URL:
            cursor.execute("""CREATE TABLE IF NOT EXISTS users (
                id UUID PRIMARY KEY, email TEXT NOT NULL, password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('user','moderator','analyst')))""")
            cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_users_email ON users(lower(email))")
        cursor.execute("""CREATE TABLE IF NOT EXISTS auth_sessions (
            token_hash TEXT PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id)
            ON DELETE CASCADE, expires_at BIGINT NOT NULL)""")


def create_account(cursor, email, password, role):
    if (len(email) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email)
            or len(password) < 12 or len(password.encode()) > 72):
        return None, "invalid"
    account_id = str(uuid.uuid4())
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    execute(cursor, """INSERT INTO users(id,email,password_hash,role)
            VALUES (?,?,?,?) ON CONFLICT DO NOTHING""", (account_id, email, hashed, role))
    return (account_id, "") if cursor.rowcount else (None, "exists")


def cookie_hash(env):
    cookies = SimpleCookie()
    try:
        cookies.load(env.get("HTTP_COOKIE", ""))
    except CookieError:
        return ""
    token = cookies.get(COOKIE)
    return hashlib.sha256(token.value.encode()).hexdigest() if token else ""


def account_view(user, query):
    signup = query.get("mode") == ["signup"]
    message = MESSAGES.get(query.get("message", [""])[0], "")
    if user:
        title = "Your account"
        email, role = map(html.escape, user)
        content = f"""<p>Signed in as <strong>{email}</strong></p><p>Role: {role}</p>
            <form class="row" method="post" action="/auth/logout"><button>Sign out</button></form>"""
    else:
        title = "Create an account" if signup else "Sign in"
        action = "signup" if signup else "login"
        autocomplete = "new-password" if signup else "current-password"
        toggle = ('<a href="/#sign-in">Already registered? Sign in</a>' if signup else
                  '<a href="/?mode=signup#sign-in">Create an account</a>')
        hint = '<p class="hint">Use at least 12 characters.</p>' if signup else ""
        content = f"""<form class="account-form" method="post" action="/auth/{action}">
            <label class="field" for="account-email">Email</label>
            <input id="account-email" name="email" type="email" maxlength="254"
                   autocomplete="email" required>
            <label class="field" for="account-password">Password</label>
            <input id="account-password" name="password" type="password"
                   autocomplete="{autocomplete}" required>{hint}
            <div class="row"><button class="primary">{title}</button></div>
            </form><p class="note">{toggle}</p>"""
    notice = f'<p role="status">{message}</p>' if message else ""
    return f'<main id="v-signin" class="hidden"><h1>{title}</h1><div class="panel">{notice}{content}</div></main>'


def application(env, start):
    def respond(status, body=b"", headers=()):
        start(status, [("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff"),
                       ("X-Frame-Options", "DENY"), *headers])
        return [body]

    path = env["PATH_INFO"]
    host = env.get("HTTP_HOST", "")
    method = env["REQUEST_METHOD"]
    if host not in HOSTS:
        return respond("403 Forbidden")
    if method == "GET" and path.lstrip("/") in ASSETS:
        asset = ROOT / path.lstrip("/")
        if asset.is_file():
            return respond("200 OK", asset.read_bytes(), [("Content-Type", mimetypes.guess_type(asset)[0])])
    if method == "GET" and path in ("/", "/index.html"):
        with database() as cursor:
            user = execute(cursor, """SELECT email,role FROM users JOIN auth_sessions
                ON users.id=auth_sessions.user_id WHERE token_hash=? AND expires_at>?""",
                (cookie_hash(env), int(time.time()))).fetchone()
        page = (ROOT / "index.html").read_text(encoding="utf-8")
        page = page.replace("</head>", ACCOUNT_STYLE + "\n</head>", 1)
        page = page.replace(PLACEHOLDER, account_view(user, parse_qs(env["QUERY_STRING"])))
        if user:
            page = re.sub(r'(class="signin">)\s*Sign in', r'\1Account', page, count=1)
        return respond("200 OK", page.encode(), [("Content-Type", "text/html; charset=utf-8")])
    if method != "POST" or path not in ("/auth/signup", "/auth/login", "/auth/logout"):
        return respond("404 Not Found")
    if env.get("HTTP_ORIGIN") != "http://" + host:
        return respond("403 Forbidden")
    if env.get("CONTENT_TYPE", "").split(";")[0] != "application/x-www-form-urlencoded":
        return respond("415 Unsupported Media Type")
    try:
        size = int(env.get("CONTENT_LENGTH") or 0)
        if not 0 <= size <= 4096:
            return respond("413 Payload Too Large")
        form = parse_qs(env["wsgi.input"].read(size).decode(), max_num_fields=8)
    except (ValueError, UnicodeError):
        return respond("400 Bad Request")

    email = form.get("email", [""])[0].strip().lower()
    password = form.get("password", [""])[0]
    destination = "/#sign-in"
    headers = []
    now = int(time.time())
    with database() as cursor:
        execute(cursor, "DELETE FROM auth_sessions WHERE expires_at<=?", (now,))
        if path == "/auth/logout":
            execute(cursor, "DELETE FROM auth_sessions WHERE token_hash=?", (cookie_hash(env),))
            destination = "/?message=out#sign-in"
            headers.append(("Set-Cookie", f"{COOKIE}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"))
        else:
            if path == "/auth/signup":
                account_id, error = create_account(cursor, email, password, "user")
            else:
                row = execute(cursor, "SELECT id,password_hash FROM users WHERE lower(email)=?",
                              (email,)).fetchone()
                account_id, error = None, "failed"
                if row:
                    if row[1].startswith("$argon2"):
                        from argon2 import PasswordHasher
                        from argon2.exceptions import VerifyMismatchError
                        try:
                            valid = PasswordHasher().verify(row[1], password)
                        except VerifyMismatchError:
                            valid = False
                    else:
                        valid = len(password.encode()) <= 72 and bcrypt.checkpw(password.encode(), row[1].encode())
                    if valid:
                        account_id, error = row[0], ""
            if error:
                mode = "&mode=signup" if path == "/auth/signup" else ""
                destination = f"/?message={error}{mode}#sign-in"
            else:
                token = secrets.token_urlsafe(32)
                digest = hashlib.sha256(token.encode()).hexdigest()
                execute(cursor, "DELETE FROM auth_sessions WHERE token_hash=?", (cookie_hash(env),))
                execute(cursor, "INSERT INTO auth_sessions VALUES (?,?,?)",
                        (digest, account_id, now + SESSION_SECONDS))
                headers.append(("Set-Cookie", f"{COOKIE}={token}; Max-Age={SESSION_SECONDS}; "
                                "Path=/; HttpOnly; SameSite=Lax"))
    return respond("303 See Other", headers=[("Location", destination), *headers])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("create-moderator").add_argument("email")
    args = parser.parse_args()
    initialize()
    if args.command == "create-moderator":
        password = getpass.getpass("New moderator password (12+ characters): ")
        if password != getpass.getpass("Confirm password: "):
            parser.exit(1, "Passwords differ.\n")
        with database() as cursor:
            _, error = create_account(cursor, args.email.strip().lower(), password, "moderator")
        if error:
            parser.exit(1, MESSAGES[error] + "\n")
        print("Moderator account created.")
        return
    if not (ROOT / "index.html").is_file() or PLACEHOLDER not in (ROOT / "index.html").read_text(encoding="utf-8"):
        parser.exit(1, "Place this file beside the ScamShield index.html with its v-signin placeholder.\n")
    with make_server("127.0.0.1", PORT, application) as server:
        print(f"Open http://localhost:{PORT}/#sign-in", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
