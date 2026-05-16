"""
Tier 1 arena — vulnerable baseline (SQLite + SQLi + CMDi).
Single-file contract: JSON POST /login and /ping. Do not import database.py.

Reset host copy with: python scripts/swap_arena_sample.py
"""
import json
import os
import platform
import sqlite3

from flask import Flask, jsonify, render_template_string, request

# --- inline database (no separate database.py per arena contract) ---
DB_PATH = os.path.join(os.path.dirname(__file__), "arena.db")


def _get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL
        )
        """
    )
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        users = [
            ("admin", "admin@zeroday.local", "supersecret123"),
            ("alice", "alice@zeroday.local", "hunter2"),
            ("bob", "bob@zeroday.local", "password"),
        ]
        cursor.executemany(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
            users,
        )
    conn.commit()
    conn.close()


def fetch_all_users():
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, password FROM users")
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


# --- Flask app (matches legacy target/app.py behavior) ---
app = Flask(__name__)

HOME_HTML = """
<!DOCTYPE html>
<html>
<head><title>Zero-Day Arena</title></head>
<body style="font-family: monospace; background: #111; color: #0f0; padding: 2rem;">
  <h1>ZERO-DAY ARENA — LOGIN</h1>
  <form id="loginForm">
    <label>USERNAME</label><br>
    <input type="text" name="username" id="username" style="width: 300px;"><br><br>
    <label>PASSWORD</label><br>
    <input type="password" name="password" id="password" style="width: 300px;"><br><br>
    <button type="submit">LOGIN</button>
  </form>
  <pre id="result" style="margin-top: 1rem;"></pre>
  <script>
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;
      const res = await fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      document.getElementById('result').textContent = JSON.stringify(await res.json(), null, 2);
    });
  </script>
</body>
</html>
"""


@app.route("/")
def home():
    return render_template_string(HOME_HTML)


@app.route("/health")
def health():
    return jsonify({"status": "alive"})


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    query = (
        "SELECT * FROM users WHERE username='"
        + username
        + "' AND password='"
        + password
        + "'"
    )

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    try:
        cursor.execute(query)
        rows = cursor.fetchall()
    except sqlite3.Error:
        conn.close()
        return jsonify({"status": "fail"})

    conn.close()

    if not rows:
        return jsonify({"status": "fail"})

    if len(rows) > 1:
        users_dump = [dict(row) for row in rows]
        return jsonify({"status": "success", "users": users_dump})

    row = dict(rows[0])
    if username.strip().lower() != row.get("username", "").lower():
        users_dump = fetch_all_users()
        return jsonify({"status": "success", "users": users_dump})

    return jsonify({"status": "success", "user": row})


@app.route("/ping", methods=["POST"])
def ping():
    data = request.get_json(silent=True) or {}
    host = data.get("host", "")

    if platform.system() == "Windows":
        cmd = "ping -n 1 " + host
    else:
        cmd = "ping -c 1 " + host

    try:
        with os.popen(cmd) as proc:
            output = proc.read()
    except OSError as exc:
        output = str(exc)

    return jsonify({"output": output})


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
