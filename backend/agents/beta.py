import re
from typing import Any, Awaitable, Callable, Optional

from journal import AttackJournal
from llm import groq_complete
from target_intel import get_prompt_attack_surface, get_seed_payload
from tools.http_exploit import fire_payload

BroadcastFn = Callable[[str, str, str], Awaitable[None]]

MAX_PAYLOAD_LEN = 80

SQLI_BLOCKED = (
    "json_extract",
    "substring(",
    "sleep(",
    "waitfor",
    "benchmark(",
    "union select",
    "information_schema",
    "char(",
    "concat(",
    "0x",
)


def _clean_payload(raw: str, vuln_type: str) -> str:
    payload = raw.strip()
    if len(payload) > 500:
        payload = payload[:500]

    if payload.startswith("```"):
        lines = payload.splitlines()
        payload = "\n".join(lines[1:-1] if len(lines) > 2 else lines).strip()

    for quote in ('"""', "'''", '"', "'"):
        if len(payload) >= 2 and payload.startswith(quote) and payload.endswith(quote):
            payload = payload[len(quote) : -len(quote)].strip()

    lowered = payload.lower()
    for prefix in (
        "username=",
        "user=",
        "password=",
        "host=",
        "login=",
        "payload=",
    ):
        if lowered.startswith(prefix):
            payload = payload[len(prefix) :].strip()
            lowered = payload.lower()

    id_match = re.match(r"^id\s*=\s*\d*(.*)$", payload, re.IGNORECASE | re.DOTALL)
    if id_match and vuln_type == "sqli":
        rest = id_match.group(1).strip()
        if rest:
            payload = rest

    return payload.strip()


def _is_absurd_payload(payload: str, vuln_type: str) -> bool:
    if not payload or len(payload) > MAX_PAYLOAD_LEN:
        return True

    lowered = payload.lower()

    if vuln_type == "sqli":
        if any(token in lowered for token in SQLI_BLOCKED):
            return True
        if payload.count("(") > 2 or payload.count("JSON") > 0:
            return True
        if lowered.startswith("id=") or "union/**/" in lowered.replace(" ", ""):
            return True
        if "sleep(" in lowered or "substring(" in lowered:
            return True
        if "'" not in payload and "or" not in lowered and "--" not in payload:
            return True

    if vuln_type == "cmdi":
        if lowered.startswith("id=") or "select " in lowered:
            return True
        if "&" not in payload and "|" not in payload and ";" not in payload:
            return True
        if len(payload) > 60:
            return True

    return False


def _pick_payload(
    raw_payload: str,
    vuln_type: str,
    attempt: int,
    journal: AttackJournal,
    scan_id: str = "",
) -> tuple[str, bool]:
    """Returns (payload, used_seed_fallback)."""
    seed = get_seed_payload(vuln_type, attempt, scan_id or None)
    cleaned = _clean_payload(raw_payload, vuln_type)

    if _is_absurd_payload(cleaned, vuln_type):
        return seed, True

    for entry in journal.get_entries():
        if entry.get("payload") == cleaned:
            return seed, True

    return cleaned, False


def _beta_rules(vuln_type: str) -> str:
    vt = vuln_type.lower().strip()
    if vt == "cmdi":
        return (
            f"- Payload MUST be under {MAX_PAYLOAD_LEN} characters.\n"
            "- Command injection: the JSON value is joined into a shell ping command.\n"
            "- Use shell chaining: & | or ; with a harmless marker (e.g. echo HACKED).\n"
            "- Output ONLY the raw host/payload value — no key=value or JSON.\n"
        )
    return (
        f"- Payload MUST be under {MAX_PAYLOAD_LEN} characters.\n"
        "- Use ONLY simple SQLite login-bypass strings (quotes, OR, -- or /* comments).\n"
        "- NEVER use JSON_EXTRACT, UNION SELECT, SLEEP, WAITFOR, or nested functions.\n"
        "- Output ONLY the raw payload — no JSON keys, no explanation.\n"
    )


async def run_beta(
    target_url: str,
    vuln_type: str,
    alpha_results: list[str],
    journal: AttackJournal,
    broadcast_fn: BroadcastFn,
    attempt: int = 1,
    workflow_id: str = "",
    parent_span_id: Optional[str] = None,
    scan_id: str = "",
) -> dict[str, Any]:
    intel = "\n".join(alpha_results[:8]) if alpha_results else "No recon results."
    surface = get_prompt_attack_surface(scan_id or None, vuln_type, target_url)
    seed = get_seed_payload(vuln_type, attempt, scan_id or None)
    rules = _beta_rules(vuln_type)

    system_prompt = (
        "You are Beta, an elite exploitation agent.\n"
        f"{surface}\n"
        "ATTACK JOURNAL (everything tried so far — do NOT repeat any of these):\n"
        f"{journal.get_context_string()}\n"
        "RULES:\n"
        f"{rules}"
        "Your task: Generate exactly ONE new payload for the injection field in the surface above."
    )
    user_prompt = (
        f"Attempt: {attempt}\n"
        f"Recon (summary):\n{intel}\n\n"
        f"Seed if stuck: {seed}"
    )

    raw_payload = await groq_complete(system_prompt, user_prompt)
    payload, used_seed = _pick_payload(raw_payload, vuln_type, attempt, journal, scan_id)

    if used_seed:
        await broadcast_fn(
            f"Beta: Invalid LLM payload blocked — using profile/arena seed → {payload}",
            "BETA",
            "info",
        )

    await broadcast_fn(f"Beta: Firing payload → {payload}", "BETA", "thinking")

    response = await fire_payload(
        target_url,
        vuln_type,
        payload,
        broadcast_fn,
        workflow_id=workflow_id,
        parent_span_id=parent_span_id,
        scan_id=scan_id,
    )
    await broadcast_fn(
        f"Beta: Response received — Status {response.get('status_code', 0)}",
        "BETA",
        "info",
    )

    return {"payload": payload, "response": response}
