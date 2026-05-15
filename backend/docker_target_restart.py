"""
Phase 8E — restart the Tier-1 `target` service so mounted arena/source/app.py is loaded,
then poll /health until the container answers.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from arena_util import ROOT_DIR, arena_target_health


def auto_restart_enabled() -> bool:
    raw = os.getenv("AUTO_RESTART_TARGET", "true").strip().lower()
    return raw in ("1", "true", "yes", "on")


def compose_project_dir() -> Path:
    override = os.getenv("DOCKER_COMPOSE_CWD", "").strip()
    if override:
        return Path(override).expanduser().resolve()
    return ROOT_DIR


def compose_service_name() -> str:
    return os.getenv("DOCKER_COMPOSE_SERVICE", "target").strip() or "target"


def _health_max_wait_s() -> float:
    try:
        return float(os.getenv("TARGET_HEALTH_MAX_WAIT_SECONDS", "90"))
    except ValueError:
        return 90.0


def _health_poll_interval_s() -> float:
    try:
        return float(os.getenv("TARGET_HEALTH_POLL_INTERVAL", "1.5"))
    except ValueError:
        return 1.5


def restart_target_container_sync(service: str) -> tuple[int, str, str]:
    cwd = compose_project_dir()
    cmd = ["docker", "compose", "restart", service]
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=120,
    )
    out = ((proc.stdout or "") + (proc.stderr or "")).strip()
    return proc.returncode, out, str(cwd)


async def restart_target_container(service: str | None = None) -> dict[str, Any]:
    svc = service or compose_service_name()

    def _run() -> tuple[int, str, str]:
        return restart_target_container_sync(svc)

    code, output, cwd = await asyncio.to_thread(_run)
    return {
        "ok": code == 0,
        "returncode": code,
        "output": output[-4000:] if output else "",
        "cwd": cwd,
        "service": svc,
    }


async def wait_target_healthy(target_url: str) -> dict[str, Any]:
    """Poll GET /health until success or timeout."""
    deadline = time.monotonic() + _health_max_wait_s()
    interval = _health_poll_interval_s()
    attempts = 0
    last: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        attempts += 1
        last = await arena_target_health(target_url)
        if last.get("reachable"):
            return {
                "ok": True,
                "attempts": attempts,
                "last": last,
            }
        await asyncio.sleep(interval)
    return {
        "ok": False,
        "attempts": attempts,
        "error": "timeout waiting for /health",
        "last": last or {},
    }
