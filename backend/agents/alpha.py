import asyncio
import json
import re
from typing import Any, Awaitable, Callable, Optional

from journal import AttackJournal
from llm import groq_complete
from target_analyzer import analyze_and_store_profile
from target_intel import get_prompt_attack_surface, is_fast_scan
from tools.web_search import search_exploits
from tracing import trace_step

BroadcastFn = Callable[[str, str, str], Awaitable[None]]


def _parse_queries(raw: str) -> list[str]:
    raw = raw.strip()
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return [str(q).strip() for q in parsed[:3] if str(q).strip()]
    except json.JSONDecodeError:
        pass

    match = re.search(r"\[.*\]", raw, re.DOTALL)
    if match:
        try:
            parsed = json.loads(match.group())
            if isinstance(parsed, list):
                return [str(q).strip() for q in parsed[:3] if str(q).strip()]
        except json.JSONDecodeError:
            pass

    lines = [line.strip(" \"'-") for line in raw.splitlines() if line.strip()]
    return lines[:3] if lines else [raw[:120]]


async def run_alpha(
    target_url: str,
    vuln_type: str,
    journal: AttackJournal,
    broadcast_fn: BroadcastFn,
    workflow_id: str = "",
    parent_span_id: Optional[str] = None,
    scan_id: str = "",
) -> dict[str, Any]:
    await broadcast_fn(
        f"Alpha: Starting recon on {target_url} for {vuln_type}",
        "ALPHA",
        "info",
    )

    if scan_id and workflow_id:
        trace_step(
            workflow_id,
            "ALPHA_PROFILE",
            parent_span_id,
            {"scan_id": scan_id},
            "started",
        )
    if scan_id:
        await analyze_and_store_profile(scan_id, vuln_type, broadcast_fn)

    system_prompt = (
        "You are Alpha, an elite reconnaissance agent. Given a target URL and "
        "vulnerability type, generate 3 specific, targeted web search queries to "
        "find real PoC payloads and bypass techniques for this exact environment. "
        "Output ONLY a JSON array of 3 search query strings, nothing else."
    )
    surface = get_prompt_attack_surface(scan_id or None, vuln_type, target_url)
    user_prompt = (
        f"Target URL: {target_url}\nVulnerability type: {vuln_type}\n\n{surface}\n"
        "Search for payloads that match this exact JSON POST injection point."
    )

    raw = await groq_complete(system_prompt, user_prompt)
    queries = _parse_queries(raw)
    search_count = 2 if is_fast_scan() else 3
    queries = queries[:search_count]
    pause = 1.0 if is_fast_scan() else 2.0

    all_snippets: list[str] = []
    for index, query in enumerate(queries, start=1):
        snippets = await search_exploits(
            query, broadcast_fn, workflow_id, parent_span_id, index
        )
        all_snippets.extend(snippets)
        if index < len(queries):
            await asyncio.sleep(pause)

    await broadcast_fn(
        f"Alpha: Recon complete. Found {len(all_snippets)} intelligence sources.",
        "ALPHA",
        "success",
    )

    return {"queries": queries, "results": all_snippets}
