import asyncio
import os
from typing import Awaitable, Callable, Literal

from agents.alpha import run_alpha
from agents.beta import run_beta
from agents.gamma import run_gamma
from blue_orchestrator import run_blue_swarm
from journal import AttackJournal, LOGS_DIR
from target_intel import is_fast_scan
from tools.file_ops import write_log
from tools.http_exploit import summarize_response
from tracing import end_workflow, reset_workflow_context, start_workflow, trace_step

BroadcastFn = Callable[[str, str, str], Awaitable[None]]
ScanOutcome = Literal["breached", "failed", "error"]

MAX_RETRIES = 4


async def run_scan(
    scan_id: str,
    target_url: str,
    vuln_type: str,
    broadcast_fn: BroadcastFn,
    journal: AttackJournal,
    trigger: str = "manual",
) -> ScanOutcome:
    reset_workflow_context()
    workflow_id, root_span = start_workflow(
        f"scan-{scan_id}",
        {
            "scan_id": scan_id,
            "target_url": target_url,
            "vuln_type": vuln_type,
            "trigger": trigger,
        },
    )

    journal.reset()
    target_url = target_url.rstrip("/")
    vuln_type = vuln_type.lower().strip()
    outcome: ScanOutcome = "failed"

    await broadcast_fn(
        f"Orchestrator: Red Swarm engaging {target_url} ({vuln_type})",
        "SYSTEM",
        "info",
    )

    alpha_span = trace_step(
        workflow_id,
        "ALPHA_RECON",
        root_span,
        {"target_url": target_url, "vuln_type": vuln_type},
        "started",
    )

    try:
        alpha_data = await run_alpha(
            target_url,
            vuln_type,
            journal,
            broadcast_fn,
            workflow_id,
            alpha_span,
            scan_id,
        )
    except Exception as exc:
        await broadcast_fn(f"Alpha failed: {exc}", "ALPHA", "error")
        outcome = "error"
        end_workflow(workflow_id, outcome)
        return outcome

    alpha_results = alpha_data.get("results", [])

    for attempt in range(1, MAX_RETRIES + 1):
        beta_span = trace_step(
            workflow_id,
            f"BETA_STRIKE_ATTEMPT_{attempt}",
            alpha_span,
            {"attempt": attempt},
            "started",
        )

        try:
            beta_data = await run_beta(
                target_url,
                vuln_type,
                alpha_results,
                journal,
                broadcast_fn,
                attempt=attempt,
                workflow_id=workflow_id,
                parent_span_id=beta_span,
                scan_id=scan_id,
            )
        except Exception as exc:
            await broadcast_fn(f"Beta failed: {exc}", "BETA", "error")
            outcome = "error"
            end_workflow(workflow_id, outcome)
            return outcome

        payload = beta_data.get("payload", "")
        response = beta_data.get("response", {})
        summary = summarize_response(response)

        if response.get("is_breach"):
            journal.add_entry(
                attempt_number=attempt,
                vuln_type=vuln_type,
                payload=payload,
                server_response_summary=summary,
                gamma_critique="",
                outcome="breached",
            )

            trace_step(
                workflow_id,
                "JOURNAL_WRITE",
                beta_span,
                {"attempt": attempt, "outcome": "breached"},
                "completed",
            )

            log_path = os.path.join(LOGS_DIR, f"{scan_id}.json")
            journal.to_file(log_path)
            log_file = write_log(
                scan_id,
                f"BREACH CONFIRMED\nPayload: {payload}\nResponse: {summary}\n",
            )

            trace_step(
                workflow_id,
                "FILE_WRITTEN",
                beta_span,
                {"path": log_file},
                "completed",
            )

            trace_step(
                workflow_id,
                "BREACH_CONFIRMED",
                beta_span,
                {"payload": payload, "response_summary": summary},
                "breached",
            )

            await broadcast_fn(
                f"BREACH CONFIRMED — payload succeeded: {payload}",
                "SYSTEM",
                "breach",
            )

            blue_span = trace_step(
                workflow_id,
                "BLUE_SWARM",
                beta_span,
                {"scan_id": scan_id},
                "started",
            )
            await run_blue_swarm(
                scan_id,
                target_url,
                vuln_type,
                journal,
                broadcast_fn,
                workflow_id,
                blue_span,
            )

            outcome = "breached"
            end_workflow(workflow_id, outcome)
            return outcome

        gamma_span = trace_step(
            workflow_id,
            f"GAMMA_CRITIQUE_{attempt}",
            beta_span,
            {"payload": payload},
            "started",
        )

        try:
            critique = await run_gamma(
                payload,
                response,
                vuln_type,
                journal,
                broadcast_fn,
                workflow_id=workflow_id,
                parent_span_id=gamma_span,
            )
        except Exception as exc:
            critique = f"Gamma unavailable: {exc}"
            await broadcast_fn(critique, "GAMMA", "error")

        journal.add_entry(
            attempt_number=attempt,
            vuln_type=vuln_type,
            payload=payload,
            server_response_summary=summary,
            gamma_critique=critique,
            outcome="failed",
        )

        trace_step(
            workflow_id,
            "JOURNAL_WRITE",
            gamma_span,
            {"attempt": attempt, "outcome": "failed"},
            "completed",
        )

        await asyncio.sleep(1.0 if is_fast_scan() else 2.0)

    await broadcast_fn(
        "Red Swarm exhausted all attempts. Target hardened or scope exceeded.",
        "SYSTEM",
        "error",
    )

    log_path = os.path.join(LOGS_DIR, f"{scan_id}.json")
    journal.to_file(log_path)
    log_file = write_log(scan_id, journal.get_context_string())

    trace_step(
        workflow_id,
        "FILE_WRITTEN",
        root_span,
        {"path": log_file},
        "completed",
    )

    outcome = "failed"
    end_workflow(workflow_id, outcome)
    return outcome
