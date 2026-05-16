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
    target_restarted = bool(zeta_result.get("target_restarted"))
    target_health_ok = zeta_result.get("target_health_ok")

    if live_still:
        if target_restarted and target_health_ok is True:
            note = (
                "Container was restarted and /health responded, but the live HTTP "
                "exploit probe still reports success — check breach markers, profile "
                "field mapping, or whether the running container matches the patched file."
            )
        elif target_restarted and target_health_ok is False:
            note = (
                "`docker compose restart` ran but /health did not recover before the "
                "timeout — inspect container logs. The arena file on disk was still updated."
            )
        elif target_restarted:
            note = (
                "Restart completed; live check still shows a breach — verify Docker and "
                "mount paths."
            )
        else:
            note = (
                "Arena file on disk was updated; automatic container restart did not run "
                "or failed — run `docker compose restart target` so the live server loads "
                "the fix. Logic simulation confirms the exploit class is blocked."
            )
    else:
        if target_restarted:
            note = (
                "Patch verified — Docker target was restarted, /health recovered, and "
                "the live arena no longer accepts the winning exploit."
            )
        else:
            note = (
                "Patch verified — winning payload blocked in simulation and on live target."
            )

    pr_url: str | None = None
    if logic_ok:
        from arena_util import arena_app_path
        from github_remediation_pr import open_remediation_pr

        try:
            remediated = arena_app_path().read_text(encoding="utf-8")
            pr_body = (
                f"**Fix summary (Epsilon)**\n{epsilon_result.get('fix_summary', '')}\n\n"
                f"**Diagnosis (Delta)**\n{delta_result.get('diagnosis', '')}"
            )[:12000]
            pr_out = await open_remediation_pr(
                scan_id,
                broadcast_fn,
                remediated,
                summary=pr_body,
            )
            pr_url = pr_out.get("url")
        except Exception as exc:
            await broadcast_fn(f"Phase 9: PR step error — {exc}", "SYSTEM", "error")

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
        used_template_fallback=bool(epsilon_result.get("used_template_fallback")),
        arena_source_path=epsilon_result.get("arena_source_path"),
        target_restarted=target_restarted,
        target_health_ok=target_health_ok,
        pr_url=pr_url,
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
