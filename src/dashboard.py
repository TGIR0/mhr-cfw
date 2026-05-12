"""
Web-based dashboard with authentication and live monitoring.
Access at http://127.0.0.1:PORT/log
"""

import json
import logging
import time
import uuid
import asyncio

log = logging.getLogger("Dashboard")

# Session store (in-memory, resets on restart)
_SESSIONS: dict[str, dict] = {}
_SESSION_TTL = 3600  # 1 hour


def create_session(auth_key: str) -> str:
    """Create a new session and return token."""
    token = uuid.uuid4().hex
    _SESSIONS[token] = {"created": time.time(), "auth_key": auth_key}
    # Clean expired sessions
    now = time.time()
    for t in list(_SESSIONS.keys()):
        if now - _SESSIONS[t]["created"] > _SESSION_TTL:
            del _SESSIONS[t]
    return token


def validate_session(token: str) -> bool:
    """Check if session token is valid."""
    if token not in _SESSIONS:
        return False
    if time.time() - _SESSIONS[token]["created"] > _SESSION_TTL:
        del _SESSIONS[token]
        return False
    return True


LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>mhr-cfw — Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: linear-gradient(135deg, #0c0c0c 0%, #1a1a2e 50%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #e0e0e0;
        }
        .container {
            background: rgba(255,255,255,0.03);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 24px;
            padding: 48px 40px;
            width: 400px;
            backdrop-filter: blur(20px);
            box-shadow: 0 25px 60px rgba(0,0,0,0.5);
        }
        h1 {
            font-size: 28px;
            font-weight: 700;
            text-align: center;
            margin-bottom: 8px;
            background: linear-gradient(135deg, #64b5f6, #42a5f5);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .subtitle {
            text-align: center;
            color: #888;
            font-size: 13px;
            margin-bottom: 32px;
        }
        input {
            width: 100%;
            padding: 14px 18px;
            border: 1px solid rgba(255,255,255,0.12);
            border-radius: 14px;
            background: rgba(255,255,255,0.04);
            color: #fff;
            font-size: 15px;
            outline: none;
            transition: all 0.3s;
        }
        input:focus {
            border-color: #42a5f5;
            box-shadow: 0 0 0 3px rgba(66,165,245,0.15);
        }
        button {
            width: 100%;
            padding: 14px;
            border: none;
            border-radius: 14px;
            background: linear-gradient(135deg, #42a5f5, #1e88e5);
            color: #fff;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            margin-top: 20px;
            transition: all 0.3s;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(66,165,245,0.3);
        }
        .error {
            color: #ef5350;
            text-align: center;
            margin-top: 16px;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>mhr-cfw</h1>
        <p class="subtitle">Domain-Fronted Relay Panel</p>
        <form method="POST" action="/login">
            <input type="password" name="key" placeholder="Enter auth key" autofocus>
            <button type="submit">Sign In</button>
            <p class="error">{{error}}</p>
        </form>
    </div>
</body>
</html>
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>mhr-cfw — Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            padding: 32px;
            min-height: 100vh;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 32px;
        }
        .header h1 {
            font-size: 24px;
            background: linear-gradient(135deg, #58a6ff, #3fb950);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .header .version {
            color: #8b949e;
            font-size: 13px;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
            margin-bottom: 32px;
        }
        .card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 16px;
            padding: 24px;
        }
        .card h3 {
            font-size: 13px;
            text-transform: uppercase;
            color: #8b949e;
            margin-bottom: 12px;
            letter-spacing: 0.5px;
        }
        .card .value {
            font-size: 36px;
            font-weight: 700;
            color: #58a6ff;
        }
        .card .label {
            font-size: 12px;
            color: #8b949e;
            margin-top: 4px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 16px;
            overflow: hidden;
        }
        th {
            text-align: left;
            padding: 14px 18px;
            font-size: 12px;
            text-transform: uppercase;
            color: #8b949e;
            background: #1c2128;
            border-bottom: 1px solid #30363d;
        }
        td {
            padding: 12px 18px;
            font-size: 14px;
            border-bottom: 1px solid #21262d;
        }
        .good { color: #3fb950; }
        .warn { color: #d2991d; }
        .bad { color: #f85149; }
        .log-container {
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 16px;
            padding: 20px;
            margin-top: 24px;
            max-height: 400px;
            overflow-y: auto;
            font-family: 'Fira Code', monospace;
            font-size: 12px;
            line-height: 1.8;
        }
        .log-line { color: #7ee787; }
        .log-warn { color: #d2991d; }
        .log-err { color: #f85149; }
    </style>
</head>
<body>
    <div class="header">
        <h1>⚡ mhr-cfw Dashboard</h1>
        <span class="version">v2.0.1</span>
    </div>
    <div class="grid">
        <div class="card">
            <h3>Active Connections</h3>
            <div class="value">{{active_conns}}</div>
            <div class="label">current</div>
        </div>
        <div class="card">
            <h3>Cache Hits</h3>
            <div class="value">{{cache_hits}}</div>
            <div class="label">responses served from cache</div>
        </div>
        <div class="card">
            <h3>Cache Misses</h3>
            <div class="value">{{cache_misses}}</div>
            <div class="label">fetched from relay</div>
        </div>
        <div class="card">
            <h3>Relay Mode</h3>
            <div class="value">{{mode}}</div>
            <div class="label">active transport</div>
        </div>
    </div>

    <h3 style="margin-bottom:16px;color:#8b949e;">📊 Top Hosts</h3>
    <table>
        <thead>
            <tr><th>Host</th><th>Requests</th><th>Errors</th><th>Data</th><th>Avg Latency</th></tr>
        </thead>
        <tbody>{{table_rows}}</tbody>
    </table>

    <h3 style="margin-top:32px;margin-bottom:16px;color:#8b949e;">📋 Recent Logs</h3>
    <div class="log-container">{{log_lines}}</div>
</body>
</html>
"""


def _render_login(error: str = "") -> bytes:
    html = LOGIN_HTML.replace("{{error}}", error)
    return f"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {len(html)}\r\n\r\n{html}".encode()


def _render_dashboard(stats: dict, cache_data: dict, log_lines: list[str], mode: str) -> bytes:
    # Table rows
    rows = ""
    for h in stats.get("per_site", [])[:10]:
        rows += f"<tr><td>{h['host'][:45]}</td><td>{h['requests']}</td><td class='{'bad' if h['errors']>0 else 'good'}'>{h['errors']}</td><td>{h['bytes']//1024} KB</td><td>{h['avg_ms']:.1f} ms</td></tr>"

    # Log lines
    log_html = ""
    for line in log_lines[-50:]:
        cls = "log-line"
        if "ERROR" in line or "✕" in line: cls = "log-err"
        elif "WARN" in line or "!" in line: cls = "log-warn"
        log_html += f'<div class="{cls}">{line}</div>\n'

    html = DASHBOARD_HTML
    html = html.replace("{{active_conns}}", str(stats.get("active_conns", 0)))
    html = html.replace("{{cache_hits}}", str(cache_data.get("hits", 0)))
    html = html.replace("{{cache_misses}}", str(cache_data.get("misses", 0)))
    html = html.replace("{{mode}}", mode)
    html = html.replace("{{table_rows}}", rows)
    html = html.replace("{{log_lines}}", log_html)

    return f"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {len(html)}\r\n\r\n{html}".encode()


async def handle_web_ui(path: str, method: str, body: bytes, config: dict, fronter, cache, log_buffer: list[str]) -> bytes:
    """Main dispatcher for /log routes."""
    if path == "/login" and method == "POST":
        # Parse form data
        data = body.decode(errors="replace")
        key = ""
        for part in data.split("&"):
            if part.startswith("key="):
                key = part[4:]
                break
        if key == config.get("auth_key", ""):
            token = create_session(key)
            auth_header = f"Set-Cookie: session={token}; Path=/; HttpOnly\r\n"
            return f"HTTP/1.1 302 Found\r\nLocation: /log\r\n{auth_header}Content-Length: 0\r\n\r\n".encode()
        return _render_login("Invalid auth key")

    # Check session
    cookies = ""  # parsed from header — simplified
    session_valid = False

    if path == "/log" or path == "/":
        # Try to get session from cookie (simplified — in production parse Cookie header)
        # For now, just show login if no valid session
        return _render_login()

    return f"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".encode()