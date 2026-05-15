"""LLM full-file rewrite for arena/source/app.py (Phase 8D)."""

from __future__ import annotations

import re

from llm import groq_complete


def _strip_markdown_fences(raw: str) -> str:
    text = raw.strip()
    if text.startswith("```"):
        text = re.sub(r"^```\w*\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()


async def llm_rewrite_arena(
    source: str,
    vuln_type: str,
    diagnosis: str,
    winning_payload: str,
) -> str | None:
    vt = vuln_type.lower().strip()
    payload_q = repr(winning_payload)[:500]

    if vt == "cmdi":
        fix_rules = (
            "Remove command injection: do NOT build shell strings from user input. "
            "Use subprocess.run with a fixed argv list of strings (e.g. "
            "['ping', '-c' or '-n', '1', host]). "
            "Validate `host` with re.match(r'^[a-zA-Z0-9.\\\\-]+$', host) "
            "and return jsonify({\"error\":\"invalid host\"}), 400 if invalid. "
            "Add `import re` and `import subprocess` if missing. "
            "Keep Flask routes, JSON shape, and response format."
        )
    else:
        fix_rules = (
            "Remove SQL injection: never concatenate user input into SQL strings. "
            "Use sqlite3 parameterized queries: "
            'cursor.execute("... WHERE col=? AND col2=?", (user, pw)). '
            "Preserve login logic, JSON responses, fetch_all_users behavior, and routes."
        )

    system = (
        "You are a senior Python security engineer. Output ONLY the complete fixed "
        "Python source file. No markdown fences, no commentary before or after the code. "
        "The file must be syntactically valid Python 3.11+ and runnable as the main Flask app.\n"
        f"{fix_rules}"
    )
    user = (
        f"Vulnerability class (this scan): {vt}\n"
        f"Winning exploit payload (for context): {payload_q}\n"
        f"Blue-team diagnosis:\n{diagnosis[:3000]}\n\n"
        f"--- CURRENT app.py ---\n{source[:26000]}"
    )

    try:
        raw = await groq_complete(system, user, max_tokens=12000)
    except Exception:
        return None

    out = _strip_markdown_fences(raw)
    if not out or len(out) < 200:
        return None
    return out
