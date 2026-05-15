from typing import Any, Awaitable, Callable, Optional

from journal import AttackJournal
from llm import groq_complete
from patch_templates import build_remediation

BroadcastFn = Callable[[str, str, str], Awaitable[None]]


async def run_delta(
    vuln_type: str,
    winning_payload: str,
    journal: AttackJournal,
    broadcast_fn: BroadcastFn,
    workflow_id: str = "",
    parent_span_id: Optional[str] = None,
) -> dict[str, Any]:
    template = build_remediation(vuln_type, winning_payload)

    system_prompt = (
        "You are Delta, a defensive security analyst on the blue team.\n"
        "A red-team agent just breached the target. Explain the vulnerability in "
        "plain technical language for a judge demo: root cause, attack vector, "
        "and impact. Reference the exact winning payload.\n"
        "Output 3-4 sentences max. No markdown headings."
    )
    user_prompt = (
        f"Vulnerability type: {vuln_type}\n"
        f"Winning payload: {winning_payload}\n"
        f"Affected file: {template['file_hint']}\n"
        f"CWE: {template['cwe']}\n"
        f"Attack journal:\n{journal.get_context_string()}\n"
        f"Known fix class: {template['fix_summary']}"
    )

    await broadcast_fn("Delta: Analyzing breach and drafting diagnosis...", "DELTA", "thinking")

    try:
        diagnosis = await groq_complete(system_prompt, user_prompt)
    except Exception as exc:
        diagnosis = (
            f"Confirmed {vuln_type} breach via payload `{winning_payload}`. "
            f"{template['fix_summary']} ({template['cwe']})"
        )
        await broadcast_fn(f"Delta: LLM unavailable, using template diagnosis — {exc}", "DELTA", "error")

    await broadcast_fn(f"Delta: {diagnosis}", "DELTA", "info")

    return {
        "diagnosis": diagnosis,
        "cwe": template["cwe"],
        "file_hint": template["file_hint"],
        "fix_summary": template["fix_summary"],
    }
