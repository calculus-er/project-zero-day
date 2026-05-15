from typing import Awaitable, Callable

from agents.delta import run_delta
from agents.epsilon import run_epsilon
from agents.zeta import run_zeta
from journal import AttackJournal
from remediation import remediation
from tracing import trace_step

BroadcastFn = Callable[[str, str, str], Awaitable[None]]


async def run_blue_swarm(
    scan_id: str,
    target_url: str,
    vuln_type: str,
    journal: AttackJournal,
    broadcast_fn: BroadcastFn,
    workflow_id: str = "",
    parent_span_id: str | None = None,
) -> bool:
    winning_payload = journal.get_winning_payload()
    if not winning_payload:
        return False

    remediation.start(scan_id, vuln_type, winning_payload)

    await broadcast_fn(
        "Orchestrator: Blue Swarm engaging — post-breach remediation",
        "SYSTEM",
        "info",
    )

    delta_span = trace_step(
        workflow_id,
        "DELTA_DIAGNOSIS",
        parent_span_id,
        {"scan_id": scan_id, "vuln_type": vuln_type},
        "started",
    )

    try:
        delta_result = await run_delta(
            vuln_type,
            winning_payload,
            journal,
            broadcast_fn,
            workflow_id,
            delta_span,
        )
    except Exception as exc:
        remediation.fail(str(exc))
        await broadcast_fn(f"Delta failed: {exc}", "DELTA", "error")
        return False

    epsilon_span = trace_step(
        workflow_id,
        "EPSILON_PATCH",
        delta_span,
        {"scan_id": scan_id},
        "started",
    )

    try:
        epsilon_result = await run_epsilon(
            scan_id,
            vuln_type,
            winning_payload,
            delta_result,
            broadcast_fn,
            workflow_id,
            epsilon_span,
        )
    except Exception as exc:
        remediation.fail(str(exc))
        await broadcast_fn(f"Epsilon failed: {exc}", "EPSILON", "error")
        return False

    zeta_span = trace_step(
        workflow_id,
        "ZETA_VERIFY",
        epsilon_span,
        {"payload": winning_payload[:120]},
        "started",
    )

    try:
        zeta_result = await run_zeta(
            target_url,
            vuln_type,
            winning_payload,
            broadcast_fn,
            workflow_id,
            zeta_span,
            scan_id,
        )
    except Exception as exc:
        remediation.fail(str(exc))
        await broadcast_fn(f"Zeta failed: {exc}", "ZETA", "error")
        return False

    logic = zeta_result.get("logic", {})
    live = zeta_result.get("live", {})
    logic_ok = bool(logic.get("logic_ok"))
    live_still = bool(live.get("still_breach"))

    if live_still:
        note = (
            "Patch logic blocks the exploit in simulation. "
            "Live arena still vulnerable until you apply the patch and rebuild Docker."
        )
    else:
        note = "Patch verified — winning payload blocked in simulation and on live target."

    remediation.complete(
        diagnosis=delta_result.get("diagnosis", ""),
        fix_summary=epsilon_result.get("fix_summary", ""),
        patch_path=epsilon_result.get("patch_path", ""),
        patch_filename=epsilon_result.get("patch_filename", ""),
        diff_preview=epsilon_result.get("diff_preview", ""),
        verified=logic_ok,
        logic_verified=logic_ok,
        live_still_vulnerable=live_still,
        verification_note=note,
    )

    trace_step(
        workflow_id,
        "REMEDIATION_COMPLETE",
        zeta_span,
        {
            "patch": epsilon_result.get("patch_filename"),
            "logic_verified": logic_ok,
            "live_still_vulnerable": live_still,
        },
        "completed" if logic_ok else "failed",
    )

    if not logic_ok:
        await broadcast_fn(
            "Blue Swarm finished — patch failed verification",
            "SYSTEM",
            "error",
        )
        return False

    await broadcast_fn(
        "Blue Swarm complete — patch verified against winning exploit",
        "SYSTEM",
        "success",
    )
    return True
