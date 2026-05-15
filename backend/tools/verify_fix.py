"""Verify remediation blocks the same payload that breached the target."""

import os
import platform
import re
import sqlite3
import subprocess
from typing import Any

from tools.http_exploit import _detect_breach, fire_payload


def _seed_db(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL
        )
        """
    )
    conn.execute("DELETE FROM users")
    conn.executemany(
        "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
        [
            ("admin", "admin@zeroday.local", "supersecret123"),
            ("alice", "alice@zeroday.local", "hunter2"),
            ("bob", "bob@zeroday.local", "password"),
        ],
    )
    conn.commit()


def _sqli_vulnerable(username: str, password: str) -> dict[str, Any]:
    """Mirror vulnerable target/app.py login()."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    _seed_db(conn)
    query = (
        "SELECT * FROM users WHERE username='"
        + username
        + "' AND password='"
        + password
        + "'"
    )
    try:
        rows = conn.execute(query).fetchall()
    except sqlite3.Error:
        conn.close()
        return {"status": "fail", "body": '{"status":"fail"}', "is_breach": False}
    conn.close()

    if not rows:
        return {"status": "fail", "body": '{"status":"fail"}', "is_breach": False}
    if len(rows) > 1:
        body = '{"status":"success","users":[{"username":"admin"}]}'
        return {"status": "success", "body": body, "is_breach": _detect_breach("sqli", body)}
    body = '{"status":"success","user":{"username":"admin"}}'
    return {"status": "success", "body": body, "is_breach": _detect_breach("sqli", body)}


def _sqli_hardened(username: str, password: str) -> dict[str, Any]:
    """Mirror remediated login() with parameterized query."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    _seed_db(conn)
    try:
        rows = conn.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, password),
        ).fetchall()
    except sqlite3.Error:
        conn.close()
        return {"status": "fail", "body": '{"status":"fail"}', "is_breach": False}
    conn.close()

    if not rows:
        return {"status": "fail", "body": '{"status":"fail"}', "is_breach": False}
    body = '{"status":"success","user":{"username":"' + dict(rows[0])["username"] + '"}}'
    return {"status": "success", "body": body, "is_breach": _detect_breach("sqli", body)}


def _cmdi_vulnerable(host: str) -> dict[str, Any]:
    if platform.system() == "Windows":
        cmd = "ping -n 1 " + host
    else:
        cmd = "ping -c 1 " + host
    try:
        with os.popen(cmd) as proc:
            output = proc.read()
    except OSError as exc:
        output = str(exc)
    body = '{"output": ' + repr(output) + "}"
    return {"body": body, "is_breach": _detect_breach("cmdi", body)}


def _cmdi_hardened(host: str) -> dict[str, Any]:
    if not re.match(r"^[a-zA-Z0-9.\-]+$", host):
        body = '{"error":"invalid host"}'
        return {"body": body, "is_breach": False}
    ping_args = (
        ["ping", "-n", "1", host]
        if platform.system() == "Windows"
        else ["ping", "-c", "1", host]
    )
    try:
        proc = subprocess.run(
            ping_args, capture_output=True, text=True, timeout=5, check=False
        )
        output = proc.stdout or proc.stderr or ""
    except (OSError, subprocess.TimeoutExpired) as exc:
        output = str(exc)
    body = '{"output": ' + repr(output) + "}"
    return {"body": body, "is_breach": _detect_breach("cmdi", body)}


def verify_patch_logic(vuln_type: str, payload: str) -> dict[str, Any]:
    """
    Prove the winning payload works on vulnerable code but not on remediated code.
    """
    vuln = vuln_type.lower().strip()
    password = "x"

    if vuln == "cmdi":
        vuln_res = _cmdi_vulnerable(payload)
        hard_res = _cmdi_hardened(payload)
    else:
        vuln_res = _sqli_vulnerable(payload, password)
        hard_res = _sqli_hardened(payload, password)

    exploit_works_on_vulnerable = vuln_res["is_breach"]
    patch_blocks_payload = not hard_res["is_breach"]
    logic_ok = exploit_works_on_vulnerable and patch_blocks_payload

    return {
        "logic_ok": logic_ok,
        "exploit_works_on_vulnerable": exploit_works_on_vulnerable,
        "patch_blocks_payload": patch_blocks_payload,
        "vulnerable_breach": vuln_res["is_breach"],
        "hardened_breach": hard_res["is_breach"],
    }


async def verify_live_target(
    target_url: str, vuln_type: str, payload: str, scan_id: str = ""
) -> dict[str, Any]:
    """Re-fire the winning payload at the running arena (still vulnerable until deploy)."""
    response = await fire_payload(
        target_url.rstrip("/"),
        vuln_type.lower(),
        payload,
        scan_id=scan_id,
    )
    return {
        "still_breach": response.get("is_breach", False),
        "status_code": response.get("status_code", 0),
        "summary": response.get("body", "")[:200],
    }
