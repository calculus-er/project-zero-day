from typing import Awaitable, Callable, Optional

from journal import AttackJournal
from llm import groq_complete
from tools.http_exploit import summarize_response

BroadcastFn = Callable[[str, str, str], Awaitable[None]]


async def run_gamma(
    payload: str,
    response: dict,
    vuln_type: str,
    journal: AttackJournal,
    broadcast_fn: BroadcastFn,
    workflow_id: str = "",
    parent_span_id: Optional[str] = None,
) -> str:
    summary = summarize_response(response)

    system_prompt = (
        "You are Gamma, a deep security reasoning agent.\n"
        "ATTACK JOURNAL (everything tried so far — do NOT repeat any of these):\n"
        f"{journal.get_context_string()}\n"
        "Your task: Analyze this failed exploit attempt and generate a specific "
        "technical critique explaining exactly WHY it failed and what specific "
        "technique Beta should try next. Be concrete: name the exact bypass "
        "technique (e.g. 'use UNION-based injection', 'try hex encoding', "
        "'add comment sequence --+'). Output only the critique, 2-3 sentences max."
    )
    user_prompt = (
        f"Vulnerability type: {vuln_type}\n"
        f"Payload tried: {payload}\n"
        f"Server response: {summary}"
    )

    await broadcast_fn("Gamma: Analyzing failure...", "GAMMA", "thinking")

    critique = await groq_complete(system_prompt, user_prompt)

    await broadcast_fn(f"Gamma: {critique}", "GAMMA", "info")

    return critique
