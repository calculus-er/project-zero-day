from typing import Any, Awaitable, Callable, Optional

from docker_target_restart import (
    auto_restart_enabled,
    restart_target_container,
    wait_target_healthy,
)
from tools.verify_fix import verify_live_target, verify_patch_logic

BroadcastFn = Callable[[str, str, str], Awaitable[None]]


async def run_zeta(
    target_url: str,
    vuln_type: str,
    winning_payload: str,
    broadcast_fn: BroadcastFn,
    workflow_id: str = "",
    parent_span_id: Optional[str] = None,
    scan_id: str = "",
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

    target_restarted = False
    target_health_ok: bool | None = None

    if logic["logic_ok"] and auto_restart_enabled():
        await broadcast_fn(
            "Zeta: Restarting Docker target to load patched arena…",
            "ZETA",
            "thinking",
        )
        restart = await restart_target_container()
        if restart["ok"]:
            target_restarted = True
            await broadcast_fn(
                f"Zeta: `docker compose restart {restart['service']}` succeeded — polling /health…",
                "ZETA",
                "info",
            )
            health = await wait_target_healthy(target_url)
            target_health_ok = bool(health["ok"])
            if health["ok"]:
                await broadcast_fn(
                    f"Zeta: Target healthy after {health['attempts']} attempt(s)",
                    "ZETA",
                    "success",
                )
            else:
                await broadcast_fn(
                    f"Zeta: /health did not recover in time — {health.get('error', 'unknown')}",
                    "ZETA",
                    "error",
                )
        else:
            await broadcast_fn(
                "Zeta: `docker compose restart` failed — "
                f"exit {restart['returncode']}; live check may still see old code. "
                f"Output: {restart['output'][:300]}",
                "ZETA",
                "error",
            )
    elif logic["logic_ok"] and not auto_restart_enabled():
        await broadcast_fn(
            "Zeta: AUTO_RESTART_TARGET disabled — skipping container restart",
            "ZETA",
            "info",
        )

    live = await verify_live_target(target_url, vuln_type, winning_payload, scan_id)

    if live["still_breach"]:
        hint = (
            "run `docker compose restart target` to reload arena/source/app.py (mounted volume)."
        )
        if target_restarted and target_health_ok:
            hint = (
                "container was restarted and /health is OK; payload may need a different "
                "field/marker check or the live app still differs from disk."
            )
        await broadcast_fn(
            f"Zeta: Live HTTP still breaches — {hint}",
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
        "target_restarted": target_restarted,
        "target_health_ok": target_health_ok,
    }
