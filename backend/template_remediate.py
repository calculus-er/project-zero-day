"""
Deterministic arena fixes when LLM patch fails (Phase 8D template fallback).
Best-effort regex: matches common Tier-1 Flask arena layouts.
"""

from __future__ import annotations

import re


def apply_template_remediation(vuln_type: str, source: str) -> tuple[str | None, str]:
    """Return (new_source, note) or (None, reason)."""
    vt = vuln_type.lower().strip()
    if vt == "cmdi":
        return _fix_cmdi(source)
    return _fix_sqli(source)


def _fix_sqli(source: str) -> tuple[str | None, str]:
    # Exact Tier-1 arena block (4-space indent)
    old = """    query = (
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
        rows = cursor.fetchall()"""

    new = """    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, password),
        )
        rows = cursor.fetchall()"""

    if old in source:
        return source.replace(old, new, 1), "matched canonical string-built SQL block"

    # Looser: cursor.execute(query) with string-concat query assignment above
    pat = re.compile(
        r"query = \(\s*"
        r'"SELECT \* FROM users WHERE username=\'"\s*\+\s*username\s*\+\s*'
        r'"\' AND password=\'"\s*\+\s*password\s*\+\s*"\'"\s*\)\s*'
        r"\n\s*conn = sqlite3\.connect\(DB_PATH\)\s*\n"
        r"\s*conn\.row_factory = sqlite3\.Row\s*\n"
        r"\s*cursor = conn\.cursor\(\)\s*\n"
        r"\s*try:\s*\n"
        r"\s*cursor\.execute\(query\)\s*\n"
        r"\s*rows = cursor\.fetchall\(\)",
        re.MULTILINE,
    )
    m = pat.search(source)
    if m:
        repl = (
            "    conn = sqlite3.connect(DB_PATH)\n"
            "    conn.row_factory = sqlite3.Row\n"
            "    cursor = conn.cursor()\n"
            "    try:\n"
            "        cursor.execute(\n"
            '            "SELECT * FROM users WHERE username=? AND password=?",\n'
            "            (username, password),\n"
            "        )\n"
            "        rows = cursor.fetchall()"
        )
        return pat.sub(repl, source, count=1), "matched regex string-built SQL block"

    return None, "no recognizable SQLi string-concat pattern"


def _ensure_imports(source: str, modules: list[str]) -> str:
    need = [m for m in modules if f"import {m}" not in source and f"from {m} " not in source]
    if not need:
        return source
    lines = source.splitlines()
    insert = 0
    for i, line in enumerate(lines):
        if line.startswith("import ") or line.startswith("from "):
            insert = i + 1
    for m in need:
        lines.insert(insert, f"import {m}")
        insert += 1
    return "\n".join(lines) + ("\n" if source.endswith("\n") else "")


def _fix_cmdi(source: str) -> tuple[str | None, str]:
    old = """    if platform.system() == "Windows":
        cmd = "ping -n 1 " + host
    else:
        cmd = "ping -c 1 " + host

    try:
        with os.popen(cmd) as proc:
            output = proc.read()
    except OSError as exc:
        output = str(exc)

    return jsonify({"output": output})"""

    new = """    if not re.match(r"^[a-zA-Z0-9.\\\\-]+$", host or ""):
        return jsonify({"error": "invalid host"}), 400

    ping_arg = "-n" if platform.system() == "Windows" else "-c"
    try:
        proc = subprocess.run(
            ["ping", ping_arg, "1", host],
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = proc.stdout or proc.stderr or ""
    except (OSError, subprocess.TimeoutExpired) as exc:
        output = str(exc)

    return jsonify({"output": output})"""

    if old in source:
        out = source.replace(old, new, 1)
        out = _ensure_imports(out, ["re", "subprocess"])
        return out, "matched canonical os.popen ping block"

    pat = re.compile(
        r"if platform\.system\(\) == [\"']Windows[\"']:\s*\n"
        r'\s*cmd = ["\']ping -n 1 ["\'] \+ host\s*\n'
        r"else:\s*\n"
        r'\s*cmd = ["\']ping -c 1 ["\'] \+ host\s*\n'
        r"\s*\n"
        r"\s*try:\s*\n"
        r"\s*with os\.popen\(cmd\) as proc:\s*\n"
        r"\s*output = proc\.read\(\)\s*\n"
        r"except OSError as exc:\s*\n"
        r"\s*output = str\(exc\)\s*\n"
        r"\s*\n"
        r'\s*return jsonify\(\{"output": output\}\)',
        re.MULTILINE,
    )
    if pat.search(source):
        out = pat.sub(new.strip(), source, count=1)
        out = _ensure_imports(out, ["re", "subprocess"])
        return out, "matched regex os.popen ping block"

    return None, "no recognizable os.popen ping pattern"
