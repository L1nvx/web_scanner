"""VulnLab — Deliberately vulnerable web server for WebScanner testing.

Provides realistic vulnerable endpoints with HTML forms so the crawler
can discover them automatically.  Uses a real SQLite database for SQL
injection, real file reads for LFI, real subprocess for CMDi, etc.
"""

import os
import re
import time
import sqlite3
import subprocess

import requests as ext_requests
from flask import (
    Flask, request, render_template_string, redirect,
    make_response, g, Response,
)

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "vulnlab.db")

# ── Database helpers ────────────────────────────────────────────

def get_db():
    """Get a per-request SQLite connection."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    """Create tables and seed data."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute("""
        CREATE TABLE users (
            id    INTEGER PRIMARY KEY,
            name  TEXT NOT NULL,
            email TEXT NOT NULL,
            role  TEXT DEFAULT 'user'
        )
    """)
    seed = [
        (1, "admin", "admin@vulnlab.local", "admin"),
        (2, "alice", "alice@vulnlab.local", "user"),
        (3, "bob",   "bob@vulnlab.local",   "user"),
        (4, "charlie", "charlie@vulnlab.local", "moderator"),
        (5, "secret_flag", "flag{sql1_d3t3ct3d}", "flag"),
    ]
    cur.executemany("INSERT INTO users VALUES (?,?,?,?)", seed)
    conn.commit()
    conn.close()


# ── Shared HTML layout ──────────────────────────────────────────

_LAYOUT = """<!DOCTYPE html>
<html><head><title>VulnLab — {{ title }}</title>
<style>
body{font-family:monospace;background:#111;color:#0f0;max-width:900px;margin:0 auto;padding:2rem}
a{color:#0ff}h1{color:#f00}h2{color:#ff0}
form{background:#1a1a1a;padding:1rem;border:1px solid #333;margin:1rem 0}
input,textarea{background:#222;color:#0f0;border:1px solid #444;padding:0.4rem;width:60%}
button{background:#900;color:#fff;border:none;padding:0.5rem 1rem;cursor:pointer}
pre{background:#1a1a1a;padding:1rem;border:1px solid #333;overflow-x:auto}
.result{background:#1a1a1a;padding:1rem;border:1px solid #333;margin:1rem 0}
</style></head>
<body>
<h1>🔓 VulnLab</h1>
<p><a href="/">← Home</a></p>
<h2>{{ title }}</h2>
{{ content|safe }}
</body></html>
"""


def page(title, content):
    return render_template_string(_LAYOUT, title=title, content=content)


# ══════════════════════════════════════════════════════════════════
#  HOME — index with links and forms for crawler discovery
# ══════════════════════════════════════════════════════════════════

@app.route("/")
def home():
    return page("Home", """
    <p>Deliberately vulnerable application for WebScanner testing.</p>
    <ul>
        <li><a href="/xss?q=test">Reflected XSS</a></li>
        <li><a href="/ssti?name=World">SSTI (Jinja2)</a></li>
        <li><a href="/sqli?id=1">SQL Injection</a></li>
        <li><a href="/lfi?file=hello.txt">Local File Inclusion</a></li>
        <li><a href="/cmdi?host=127.0.0.1">Command Injection</a></li>
        <li><a href="/ssrf?url=http://example.com">SSRF</a></li>
        <li><a href="/redirect?url=/">Open Redirect</a></li>
        <li><a href="/header?lang=en">Header Injection / CRLF</a></li>
    </ul>

    <hr>
    <h2>Forms (POST)</h2>

    <form action="/xss" method="POST">
        <label>XSS Search:</label><br>
        <input type="text" name="q" value="test">
        <button type="submit">Search</button>
    </form>

    <form action="/ssti" method="POST">
        <label>SSTI Name:</label><br>
        <input type="text" name="name" value="World">
        <button type="submit">Greet</button>
    </form>

    <form action="/sqli" method="POST">
        <label>SQLi User ID:</label><br>
        <input type="text" name="id" value="1">
        <button type="submit">Lookup</button>
    </form>

    <form action="/lfi" method="POST">
        <label>LFI File:</label><br>
        <input type="text" name="file" value="hello.txt">
        <button type="submit">Read</button>
    </form>

    <form action="/cmdi" method="POST">
        <label>CMDi Ping Host:</label><br>
        <input type="text" name="host" value="127.0.0.1">
        <button type="submit">Ping</button>
    </form>

    <form action="/ssrf" method="POST">
        <label>SSRF Fetch URL:</label><br>
        <input type="text" name="url" value="http://example.com">
        <button type="submit">Fetch</button>
    </form>

    <form action="/redirect" method="POST">
        <label>Redirect URL:</label><br>
        <input type="text" name="url" value="/">
        <button type="submit">Go</button>
    </form>

    <form action="/header" method="POST">
        <label>Language Header:</label><br>
        <input type="text" name="lang" value="en">
        <button type="submit">Set</button>
    </form>
    """)


# ══════════════════════════════════════════════════════════════════
#  XSS — Reflected Cross-Site Scripting
# ══════════════════════════════════════════════════════════════════

@app.route("/xss", methods=["GET", "POST"])
def xss():
    q = request.values.get("q", "test")
    # VULNERABLE: Reflected XSS — input rendered inside HTML without escaping
    result = render_template_string(
        '<div class="result"><p>Search results for: ' + q + "</p></div>"
    )
    return page("Reflected XSS", f"""
    <form method="GET" action="/xss">
        <input type="text" name="q" value="">
        <button type="submit">Search</button>
    </form>
    {result}
    """)


# ══════════════════════════════════════════════════════════════════
#  SSTI — Server-Side Template Injection (Jinja2)
# ══════════════════════════════════════════════════════════════════

@app.route("/ssti", methods=["GET", "POST"])
def ssti():
    name = request.values.get("name", "World")
    # VULNERABLE: SSTI — user input directly in template string
    greeting = render_template_string("Hello " + name + "!")
    return page("SSTI (Jinja2)", f"""
    <form method="GET" action="/ssti">
        <input type="text" name="name" value="">
        <button type="submit">Greet</button>
    </form>
    <div class="result">{greeting}</div>
    """)


# ══════════════════════════════════════════════════════════════════
#  SQLi — SQL Injection (real SQLite)
# ══════════════════════════════════════════════════════════════════

@app.route("/sqli", methods=["GET", "POST"])
def sqli():
    id_val = request.values.get("id", "")
    if not id_val:
        return page("SQL Injection", """
        <form method="GET" action="/sqli">
            <input type="text" name="id" value="1">
            <button type="submit">Lookup</button>
        </form>
        <p>Provide a user ID.</p>
        """)

    # VULNERABLE: Raw string interpolation in SQL query
    query = f"SELECT * FROM users WHERE id = '{id_val}'"
    db = get_db()

    try:
        rows = db.execute(query).fetchall()
        if rows:
            result_html = "<table><tr><th>ID</th><th>Name</th><th>Email</th><th>Role</th></tr>"
            for row in rows:
                result_html += f"<tr><td>{row['id']}</td><td>{row['name']}</td><td>{row['email']}</td><td>{row['role']}</td></tr>"
            result_html += "</table>"
        else:
            result_html = "<p>No user found.</p>"
    except Exception as e:
        # VULNERABLE: Leaking SQL error messages
        result_html = f'<p style="color:red">SQL Error: {e}</p>'

    # Simulate time-based: if SLEEP(n) appears, actually sleep
    sleep_match = re.search(r"SLEEP\((\d+)\)", id_val, re.IGNORECASE)
    if sleep_match:
        sec = min(int(sleep_match.group(1)), 10)
        time.sleep(sec)

    return page("SQL Injection", f"""
    <form method="GET" action="/sqli">
        <input type="text" name="id" value="">
        <button type="submit">Lookup</button>
    </form>
    <p><em>Query: {query}</em></p>
    {result_html}
    """)


# ══════════════════════════════════════════════════════════════════
#  LFI — Local File Inclusion
# ══════════════════════════════════════════════════════════════════

@app.route("/lfi", methods=["GET", "POST"])
def lfi():
    filename = request.values.get("file", "")
    if not filename:
        return page("Local File Inclusion", """
        <form method="GET" action="/lfi">
            <input type="text" name="file" value="hello.txt">
            <button type="submit">Read</button>
        </form>
        <p>Provide a file path.</p>
        """)

    # VULNERABLE: Path traversal — no sanitization
    if filename.startswith("/"):
        path = filename
    else:
        path = os.path.join(os.path.dirname(__file__), filename)

    try:
        if os.path.exists(path) and os.path.isfile(path):
            with open(path, "r", errors="replace") as f:
                content = f.read()
            result = f'<pre>{content}</pre>'
        else:
            result = "<p>File not found.</p>"
    except Exception as e:
        result = f'<p style="color:red">Error: {e}</p>'

    return page("Local File Inclusion", f"""
    <form method="GET" action="/lfi">
        <input type="text" name="file" value="">
        <button type="submit">Read</button>
    </form>
    {result}
    """)


# ══════════════════════════════════════════════════════════════════
#  CMDi — Command Injection
# ══════════════════════════════════════════════════════════════════

@app.route("/cmdi", methods=["GET", "POST"])
def cmdi():
    host = request.values.get("host", "")
    if not host:
        return page("Command Injection", """
        <form method="GET" action="/cmdi">
            <input type="text" name="host" value="127.0.0.1">
            <button type="submit">Ping</button>
        </form>
        <p>Provide a host to ping.</p>
        """)

    # VULNERABLE: Command injection — user input concatenated into shell command
    cmd = f"ping -c 1 {host}"
    try:
        output = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT, timeout=15
        )
        result = f"<pre>{output.decode(errors='replace')}</pre>"
    except subprocess.TimeoutExpired:
        result = "<pre>Command timed out.</pre>"
    except subprocess.CalledProcessError as e:
        result = f"<pre>{e.output.decode(errors='replace')}</pre>"
    except Exception as e:
        result = f"<pre>Error: {e}</pre>"

    return page("Command Injection", f"""
    <form method="GET" action="/cmdi">
        <input type="text" name="host" value="">
        <button type="submit">Ping</button>
    </form>
    <p><em>Command: {cmd}</em></p>
    {result}
    """)


# ══════════════════════════════════════════════════════════════════
#  SSRF — Server-Side Request Forgery
# ══════════════════════════════════════════════════════════════════

@app.route("/ssrf", methods=["GET", "POST"])
def ssrf():
    url = request.values.get("url", "")
    if not url:
        return page("SSRF", """
        <form method="GET" action="/ssrf">
            <input type="text" name="url" value="http://example.com">
            <button type="submit">Fetch</button>
        </form>
        <p>Provide a URL to fetch.</p>
        """)

    # VULNERABLE: SSRF — fetch arbitrary URL server-side
    try:
        resp = ext_requests.get(url, timeout=5, verify=False)
        content = resp.text[:5000]
        result = f'<pre>{content}</pre>'
    except Exception as e:
        result = f'<p style="color:red">Fetch error: {e}</p>'

    return page("SSRF", f"""
    <form method="GET" action="/ssrf">
        <input type="text" name="url" value="">
        <button type="submit">Fetch</button>
    </form>
    {result}
    """)


# ══════════════════════════════════════════════════════════════════
#  Open Redirect
# ══════════════════════════════════════════════════════════════════

@app.route("/redirect", methods=["GET", "POST"])
def open_redirect():
    url = request.values.get("url", "")
    if not url:
        return page("Open Redirect", """
        <form method="GET" action="/redirect">
            <input type="text" name="url" value="/">
            <button type="submit">Go</button>
        </form>
        <p>Provide a redirect URL.</p>
        """)

    # VULNERABLE: Open redirect — no validation of target URL
    return redirect(url)


# ══════════════════════════════════════════════════════════════════
#  Header Injection / CRLF
# ══════════════════════════════════════════════════════════════════

@app.route("/header", methods=["GET", "POST"])
def header_injection():
    lang = request.values.get("lang", "en")

    # VULNERABLE: CRLF injection — user input directly in header value
    # We build the response manually to allow injection
    body = page("Header Injection / CRLF", f"""
    <form method="GET" action="/header">
        <input type="text" name="lang" value="">
        <button type="submit">Set Language</button>
    </form>
    <div class="result"><p>Language set to: {lang}</p></div>
    """)

    resp = make_response(body)
    # Directly set header without sanitization — allows CRLF injection
    resp.headers["X-Custom-Language"] = lang
    return resp


# ══════════════════════════════════════════════════════════════════
#  Internal metadata endpoint (for SSRF detection)
# ══════════════════════════════════════════════════════════════════

@app.route("/internal/metadata")
def internal_metadata():
    """Simulated internal metadata — should only be reachable via SSRF."""
    return "instance-id: i-vulnlab-1337\nami-id: ami-deadbeef\nsecret-key: AKIAIOSFODNN7EXAMPLE\n"


# ══════════════════════════════════════════════════════════════════
#  Main
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    init_db()
    print("\n  🔓 VulnLab starting on http://0.0.0.0:5000\n")
    app.run(host="0.0.0.0", port=5000, debug=True)
