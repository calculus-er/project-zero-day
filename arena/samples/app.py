from __future__ import annotations

import json
import os
import platform
import sqlite3
import subprocess

from flask import Flask, jsonify, render_template_string, request

DB_PATH = os.path.join(os.path.dirname(__file__), "arena.db")


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL
        )
        """
    )
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        seed = [
            ("admin", "admin@zeroday.local", "supersecret123"),
            ("alice", "alice@zeroday.local", "hunter2"),
            ("bob", "bob@zeroday.local", "password"),
        ]
        cur.executemany(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
            seed,
        )
    conn.commit()
    conn.close()


def _dump_users():
    conn = _connect()
    cur = conn.cursor()
    cur.execute("SELECT id, username, email, password FROM users")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def create_app():
    app = Flask(__name__)

    PAGE = """
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Staging — Zero-Day</title></head>
<body style="font-family: system-ui; background:#1a1a2e; color:#eaeaea; padding:2rem;">
  <h1>STAGING TARGET</h1>
  <p>JSON POST /login and /ping only.</p>
  <form id="f">
    <label>User</label><br>
    <input id="u" style="width:280px"><br><br>
    <label>Pass</label><br>
    <input id="p" type="password" style="width:280px"><br><br>
    <button type="submit">POST /login</button>
  </form>
  <pre id="o" style="margin-top:1rem;"></pre>
  <script>
    document.getElementById('f').onsubmit = async (e) => {
      e.preventDefault();
      const r = await fetch('/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          username: document.getElementById('u').value,
          password: document.getElementById('p').value
        })
      });
      document.getElementById('o').textContent = JSON.stringify(await r.json(), null, 2);
    };
  </script>
</body>
</html>
"""

    @app.get("/")
    def root():
        return render_template_string(PAGE)

    @app.get("/health")
    def health():
        return jsonify({"status": "alive", "profile": "staging"})

    @app.post("/login")
    def login():
        body = request.get_json(silent=True) or {}
        u = body.get("username", "")
        p = body.get("password", "")

        conn = _connect()
        cur = conn.cursor()
        try:
            cur.execute(
                "SELECT * FROM users WHERE username=? AND password=?",
                (u, p),
            )
            rows = cur.fetchall()
        except sqlite3.Error:
            conn.close()
            return jsonify({"status": "fail", "reason": "db_error"})
        conn.close()

        if not rows:
            return jsonify({"status": "fail"})

        if len(rows) > 1:
            return jsonify(
                {"status": "success", "users": [dict(r) for r in rows]}
            )

        row = dict(rows[0])
        if str(u).strip().lower() != str(row.get("username", "")).strip().lower():
            return jsonify({"status": "success", "users": _dump_users()})

        return jsonify({"status": "success", "user": row})

    @app.post("/ping")
    def ping():
        body = request.get_json(silent=True) or {}
        host = body.get("host", "")
        is_win = platform.system() == "Windows"
        # Intentionally unsafe: user input embedded in a shell string.
        shell_cmd = (
            f"ping -n 1 {host}" if is_win else f"ping -c 1 {host}"
        )
        try:
            proc = subprocess.run(
                shell_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=12,
            )
            blob = (proc.stdout or "") + (proc.stderr or "")
        except (OSError, subprocess.TimeoutExpired) as exc:
            blob = str(exc)

        return jsonify({"output": blob})

    return app


app = create_app()

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)