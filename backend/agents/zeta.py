from typing import Any, Awaitable, Callable, Optional

from tools.verify_fix import verify_live_target, verify_patch_logic

BroadcastFn = Callable[[str, str, str], Awaitable[None]]


async def run_zeta(
    target_url: str,
    vuln_type: str,
    winning_payload: str,
    broadcast_fn: BroadcastFn,
    workflow_id: str = "",
    parent_span_id: Optional[str] = None,
) -> dict[str, Any]:
    await broadcast_fn(
        f"Zeta: Re-testing winning payload `{winning_payload[:60]}`…",
        "ZETA",
        "thinking",
    )

    logic = verify_patch_logic(vuln_type, winning_payload)

    if logic["exploit_works_on_vulnerable"]:
        await broadcast_fn(
            "Zeta: Confirmed — payload still breaks vulnerable code path",
            "ZETA",
            "info",
        )
    else:
        await broadcast_fn(
            "Zeta: Warning — payload did not reproduce on vulnerable simulator",
            "ZETA",
            "error",
        )

    if logic["patch_blocks_payload"]:
        await broadcast_fn(
            "Zeta: LOGIC CHECK PASS — remediated code blocks the exploit",
            "ZETA",
            "success",
        )
    else:
        await broadcast_fn(
            "Zeta: LOGIC CHECK FAIL — patch would not block this payload",
            "ZETA",
            "error",
        )

    live = await verify_live_target(target_url, vuln_type, winning_payload)

    if live["still_breach"]:
        await broadcast_fn(
            "Zeta: Live arena still exploitable (patch file not deployed to Docker yet)",
            "ZETA",
            "info",
        )
    else:
        await broadcast_fn(
            "Zeta: Live arena — exploit no longer succeeds",
            "ZETA",
            "success",
        )

    verified = logic["logic_ok"]
    return {
        "verified": verified,
        "logic": logic,
        "live": live,
    }
