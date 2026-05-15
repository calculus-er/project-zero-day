"""
Omium SDK tracing + Execution Engine runs for Project Zero-Day.
Spans only emit during active scans — never on /status or health polls.

Set OMIUM_TRACING_ENABLED=false in .env to disable completely.
"""

import os
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from omium_execution import (
    bind_execution_to_sdk,
    clear_sdk_execution,
    create_scan_execution,
    finish_scan_execution,
    set_execution_running,
)

_omium: Any = None
_enabled = False
_init_attempted = False
_active_execution_id: Optional[str] = None
_scan_metadata: dict[str, Any] = {}
_scan_tracer: Any = None
_root_span_id: Optional[str] = None


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tracing_allowed() -> bool:
    flag = os.getenv("OMIUM_TRACING_ENABLED", "true").strip().lower()
    return flag not in ("0", "false", "no", "off")


def _init_omium() -> None:
    global _omium, _enabled, _init_attempted
    _init_attempted = True

    if not _tracing_allowed():
        return

    api_key = os.getenv("OMIUM_API_KEY", "").strip()
    if not api_key:
        return

    try:
        import omium

        omium.init(
            api_key=api_key,
            project=os.getenv("OMIUM_PROJECT", "zero-day"),
            auto_trace=True,
            auto_checkpoint=False,
            flush_interval=2.0,
            debug=os.getenv("OMIUM_DEBUG", "").lower() == "true",
        )
        _omium = omium
        _enabled = True
        print("[tracing] Omium enabled (Execution Engine + SDK spans)")
    except Exception as exc:
        print(f"[tracing] Omium init skipped: {exc}")


def ensure_initialized() -> None:
    if not _init_attempted:
        _init_omium()


def is_enabled() -> bool:
    return _enabled


def get_active_execution_id() -> Optional[str]:
    """Only set while a scan is in progress (null when idle)."""
    return _active_execution_id


def reset_workflow_context() -> None:
    global _scan_tracer, _root_span_id
    _scan_tracer = None
    _root_span_id = None


def _span_type_for(step_name: str) -> str:
    upper = step_name.upper()
    if "ALPHA" in upper or "GAMMA" in upper:
        return "agent"
    if "BETA" in upper or "BREACH" in upper or "SCAN" in upper:
        return "chain"
    if "HTTP" in upper or "WEB_SEARCH" in upper or "FILE" in upper:
        return "tool"
    return "tool"


def _get_scan_tracer() -> Any:
    """One tracer per scan, tied to the Execution Engine run id."""
    global _scan_tracer
    if not _enabled:
        return None
    if _scan_tracer is not None:
        return _scan_tracer

    from omium.integrations.core import get_current_config
    from omium.integrations.tracer import OmiumTracer

    cfg = get_current_config()
    execution_id = _active_execution_id or (
        cfg.execution_id if cfg and cfg.execution_id else str(uuid.uuid4())
    )
    project = os.getenv("OMIUM_PROJECT", "zero-day")
    _scan_tracer = OmiumTracer(
        execution_id=execution_id,
        project=project,
        trace_id=execution_id,
    )
    return _scan_tracer


def flush_traces() -> None:
    tracer = _scan_tracer
    if tracer:
        try:
            tracer.flush()
        except Exception as exc:
            print(f"[tracing] flush failed: {exc}")


def _emit_span(
    step_name: str,
    parent_span_id: Optional[str],
    data: dict[str, Any],
    status: str,
) -> str:
    from omium.integrations.tracer import Span

    tracer = _get_scan_tracer()
    if not tracer:
        return str(uuid.uuid4())

    span = Span(
        span_id=str(uuid.uuid4()),
        name=step_name,
        trace_id=tracer.trace_id,
        parent_span_id=parent_span_id,
        span_type=_span_type_for(step_name),
        attributes={"status": status},
    )
    span.set_input(data)
    span.set_output({"status": status, "step": step_name})

    with tracer._lock:
        tracer._spans.append(span)

    return span.span_id


def start_workflow(
    name: str, metadata: Optional[dict[str, Any]] = None
) -> tuple[str, str]:
    global _active_execution_id, _scan_metadata, _scan_tracer, _root_span_id

    meta = dict(metadata or {})
    meta.setdefault("workflow_name", name)
    _scan_metadata = meta
    _scan_tracer = None

    execution_id = create_scan_execution(
        {
            "scan_id": meta.get("scan_id"),
            "target_url": meta.get("target_url"),
            "vuln_type": meta.get("vuln_type"),
            "trigger": meta.get("trigger", "manual"),
        }
    )

    if execution_id:
        _active_execution_id = execution_id
        workflow_id = execution_id
        if _enabled and _omium:
            bind_execution_to_sdk(execution_id, _omium)
        set_execution_running(execution_id)
        print(f"[omium] execution started: {execution_id}")
    else:
        workflow_id = str(uuid.uuid4())
        _active_execution_id = None
        if _enabled and _omium:
            bind_execution_to_sdk(workflow_id, _omium)

    data: dict[str, Any] = {"workflow": name, "timestamp": _timestamp(), **meta}
    _root_span_id = trace_step(workflow_id, "SCAN_STARTED", None, data, "started")
    flush_traces()
    return workflow_id, _root_span_id


def end_workflow(workflow_id: str, outcome: str) -> None:
    global _active_execution_id, _scan_tracer, _root_span_id

    trace_step(
        workflow_id,
        "SCAN_COMPLETE",
        _root_span_id,
        {"outcome": outcome, "timestamp": _timestamp(), **_scan_metadata},
        outcome,
    )
    flush_traces()

    if _active_execution_id:
        finish_scan_execution(
            _active_execution_id,
            outcome,
            output_data={
                "outcome": outcome,
                "scan_id": _scan_metadata.get("scan_id"),
                "target_url": _scan_metadata.get("target_url"),
                "vuln_type": _scan_metadata.get("vuln_type"),
            },
        )
        print(f"[omium] execution finished: {_active_execution_id} ({outcome})")

    if _enabled and _omium:
        clear_sdk_execution(_omium)

    _active_execution_id = None
    _scan_tracer = None


def trace_step(
    workflow_id: str,
    step_name: str,
    parent_id: Optional[str],
    data: dict[str, Any],
    status: str,
) -> str:
    """Emit one Omium span ingested to /traces/ingest for the active execution."""
    if not _enabled:
        return str(uuid.uuid4())

    payload = {
        **data,
        "workflow_id": workflow_id,
        "execution_id": _active_execution_id or workflow_id,
        "status": status,
        "timestamp": _timestamp(),
    }

    try:
        span_id = _emit_span(step_name, parent_id, payload, status)
    except Exception as exc:
        print(f"[tracing] span {step_name} failed: {exc}")
        span_id = str(uuid.uuid4())

    return span_id
