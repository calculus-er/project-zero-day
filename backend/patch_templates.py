"""Deterministic remediation patches for the Zero-Day arena target."""

from typing import Any


def build_remediation(vuln_type: str, winning_payload: str) -> dict[str, Any]:
    vuln = vuln_type.lower().strip()
    if vuln == "cmdi":
        return _cmdi_patch(winning_payload)
    return _sqli_patch(winning_payload)


def _sqli_patch(winning_payload: str) -> dict[str, Any]:
    diff = f"""--- target/app.py (vulnerable)
+++ target/app.py (remediated)
@@ login() — string concatenation SQLi
-    query = (
-        "SELECT * FROM users WHERE username='"
-        + username
-        + "' AND password='"
-        + password
-        + "'"
-    )
-    cursor.execute(query)
+    cursor.execute(
+        "SELECT * FROM users WHERE username=? AND password=?",
+        (username, password),
+    )

# Breach payload that worked: {winning_payload!r}
# Root cause: unsanitized username/password embedded in raw SQL.
# Fix: parameterized query — user input never parsed as SQL syntax.
"""
    fixed_snippet = '''
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, password),
        )
        rows = cursor.fetchall()
    except sqlite3.Error:
        conn.close()
        return jsonify({"status": "fail"})
    # ... remainder unchanged
'''
    return {
        "filename": "sqli_login_parameterized.patch",
        "diff_preview": diff.strip(),
        "fixed_snippet": fixed_snippet.strip(),
        "fix_summary": (
            "Replace string-built SQL with parameterized placeholders (?). "
            "The winning payload becomes literal data, not executable SQL."
        ),
        "cwe": "CWE-89",
        "file_hint": "target/app.py — login()",
    }


def _cmdi_patch(winning_payload: str) -> dict[str, Any]:
    diff = f"""--- target/app.py (vulnerable)
+++ target/app.py (remediated)
@@ ping() — shell injection via os.popen
-    cmd = "ping -n 1 " + host   # or ping -c 1 on Linux
-    with os.popen(cmd) as proc:
+    import re, subprocess
+    if not re.match(r'^[a-zA-Z0-9.\\-]+$', host):
+        return jsonify({{"error": "invalid host"}}), 400
+    proc = subprocess.run(
+        ["ping", "-n" if platform.system() == "Windows" else "-c", "1", host],
+        capture_output=True, text=True, timeout=5,
+    )
+    output = proc.stdout or proc.stderr

# Breach payload that worked: {winning_payload!r}
# Root cause: user-controlled host passed to shell.
# Fix: allowlist validation + subprocess without shell=True.
"""
    return {
        "filename": "cmdi_ping_subprocess.patch",
        "diff_preview": diff.strip(),
        "fixed_snippet": "",
        "fix_summary": (
            "Validate host with a strict allowlist and call subprocess with a "
            "fixed argv list — never concatenate user input into shell commands."
        ),
        "cwe": "CWE-78",
        "file_hint": "target/app.py — ping()",
    }
