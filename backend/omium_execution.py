"""
Omium Execution Engine — creates dashboard-visible runs and correlates SDK traces.

Each scan: POST /executions → set_execution_id → PATCH running → spans → PATCH completed/failed.
"""

from __future__ import annotations

import os
from typing import Any, Optional

import httpx

_workflow_id_cache: Optional[str] = None
_last_execution_id: Optional[str] = None


def _api_base() -> str:
    url = os.getenv("OMIUM_API_URL", "https://api.omium.ai").strip().rstrip("/")
    if not url.endswith("/api/v1"):
        url = f"{url}/api/v1"
    return url


def _headers() -> dict[str, str]:
    key = os.getenv("OMIUM_API_KEY", "").strip()
    return {"X-API-Key": key, "Content-Type": "application/json"}


def _enabled() -> bool:
    if os.getenv("OMIUM_TRACING_ENABLED", "true").strip().lower() in (
        "0",
        "false",
        "no",
        "off",
    ):
        return False
    return bool(os.getenv("OMIUM_API_KEY", "").strip())


def get_last_execution_id() -> Optional[str]:
    return _last_execution_id


def resolve_workflow_id() -> Optional[str]:
    """Workflow UUID for Execution Engine (env override or match by OMIUM_PROJECT name)."""
    global _workflow_id_cache

    if not _enabled():
        return None

    override = os.getenv("OMIUM_WORKFLOW_ID", "").strip()
    if override:
        _workflow_id_cache = override
        return override

    if _workflow_id_cache:
        return _workflow_id_cache

    project = os.getenv("OMIUM_PROJECT", "project-zero-day").strip()
    try:
        with httpx.Client(timeout=15.0) as client:
            response = client.get(f"{_api_base()}/workflows", headers=_headers())
        if response.status_code != 200:
            print(f"[omium] could not list workflows: HTTP {response.status_code}")
            return None

        workflows = response.json()
        if isinstance(workflows, dict):
            workflows = workflows.get("items", workflows.get("workflows", []))

        for wf in workflows:
            if wf.get("name") == project:
                _workflow_id_cache = wf["id"]
                return _workflow_id_cache

        if workflows:
            _workflow_id_cache = workflows[0]["id"]
            print(
                f"[omium] no workflow named '{project}'; using '{workflows[0].get('name')}'"
            )
            return _workflow_id_cache
    except Exception as exc:
        print(f"[omium] workflow lookup failed: {exc}")

    return None


def _agent_id(workflow_id: str) -> str:
    custom = os.getenv("OMIUM_AGENT_ID", "").strip()
    if custom:
        return custom
    return f"{workflow_id}-agent"


def create_scan_execution(input_data: dict[str, Any]) -> Optional[str]:
    """Register a run in Omium Runs/Live. Returns execution_id or None."""
    global _last_execution_id

    if not _enabled():
        return None

    workflow_id = resolve_workflow_id()
    if not workflow_id:
        return None

    body = {
        "workflow_id": workflow_id,
        "agent_id": _agent_id(workflow_id),
        "input_data": input_data,
        "metadata": {
            "source": "project-zero-day",
            "project": os.getenv("OMIUM_PROJECT", "project-zero-day"),
        },
    }

    try:
        with httpx.Client(timeout=20.0) as client:
            response = client.post(
                f"{_api_base()}/executions", headers=_headers(), json=body
            )
        if response.status_code not in (200, 201):
            print(f"[omium] create execution failed: {response.status_code} {response.text[:200]}")
            return None

        execution_id = response.json()["id"]
        _last_execution_id = execution_id
        return execution_id
    except Exception as exc:
        print(f"[omium] create execution error: {exc}")
        return None


def set_execution_running(execution_id: str) -> None:
    _patch_status(execution_id, "running")


def finish_scan_execution(
    execution_id: str,
    outcome: str,
    output_data: Optional[dict[str, Any]] = None,
    error_message: Optional[str] = None,
) -> None:
    status = "failed" if outcome in ("failed", "error") else "completed"
    payload: dict[str, Any] = {"status": status}
    if output_data:
        payload["output_data"] = output_data
    if error_message:
        payload["error_message"] = error_message
    _patch_status(execution_id, status, payload)


def _patch_status(
    execution_id: str, status: str, extra: Optional[dict[str, Any]] = None
) -> None:
    if not _enabled():
        return

    body: dict[str, Any] = {"status": status}
    if extra:
        body.update(extra)

    try:
        with httpx.Client(timeout=15.0) as client:
            response = client.patch(
                f"{_api_base()}/executions/{execution_id}/status",
                headers=_headers(),
                json=body,
            )
        if response.status_code >= 400:
            print(f"[omium] status update failed: {response.status_code} {response.text[:200]}")
    except Exception as exc:
        print(f"[omium] status update error: {exc}")


def bind_execution_to_sdk(execution_id: str, omium_module: Any) -> None:
    try:
        omium_module.set_execution_id(execution_id)
    except Exception as exc:
        print(f"[omium] set_execution_id failed: {exc}")


def clear_sdk_execution(omium_module: Any) -> None:
    try:
        omium_module.set_execution_id(None)
    except Exception:
        pass
    try:
        from omium.integrations.tracer import flush_all_tracers

        flush_all_tracers()
    except Exception:
        pass
