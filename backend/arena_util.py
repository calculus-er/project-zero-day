"""
Arena (Tier 1) — path resolution and status for the mounted arena ``*.py`` entry.
"""

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import httpx

BACKEND_DIR = Path(__file__).resolve().parent
ROOT_DIR = BACKEND_DIR.parent


def arena_source_dir() -> Path:
    rel = os.getenv("ARENA_SOURCE_DIR", "arena/source").strip()
    p = Path(rel)
    if p.is_absolute():
        return p
    return (ROOT_DIR / p).resolve()


def _arena_py_candidates(source: Path) -> list[Path]:
    return sorted(
        p
        for p in source.glob("*.py")
        if p.is_file() and not p.name.startswith("app.bak.")
    )


def resolved_arena_entry_basename() -> str:
    """
    ARENA_ENTRY_FILE: explicit filename (default ``app.py``), or ``auto`` when
    exactly one non-backup ``*.py`` exists under arena/source.
    """
    raw = (os.getenv("ARENA_ENTRY_FILE") or "app.py").strip() or "app.py"
    if raw.lower() == "auto":
        c = _arena_py_candidates(arena_source_dir())
        if len(c) == 1:
            return c[0].name
        if len(c) == 0:
            return "app.py"
        raise RuntimeError(
            "ARENA_ENTRY_FILE=auto requires exactly one non-backup .py in "
            f"{arena_source_dir()} (found {len(c)}: {[p.name for p in c]}). "
            "Set ARENA_ENTRY_FILE to a filename, enable GITHUB_DEMO_EXCLUSIVE_SYNC on sync, "
            "or remove extra scripts."
        )
    base = raw
    if not base.endswith(".py"):
        base = f"{base}.py"
    return base


def arena_app_path() -> Path:
    return arena_source_dir() / resolved_arena_entry_basename()


def arena_app_stats() -> dict[str, Any]:
    try:
        path = arena_app_path()
    except RuntimeError as exc:
        return {
            "exists": False,
            "path": None,
            "size_bytes": None,
            "modified_utc": None,
            "error": str(exc),
        }
    if not path.is_file():
        return {
            "exists": False,
            "path": str(path),
            "size_bytes": None,
            "modified_utc": None,
            "error": None,
        }
    stat = path.stat()
    return {
        "exists": True,
        "path": str(path),
        "size_bytes": stat.st_size,
        "modified_utc": datetime.fromtimestamp(
            stat.st_mtime, tz=timezone.utc
        ).isoformat(),
        "error": None,
    }


async def arena_target_health(target_url: str) -> dict[str, Any]:
    base = target_url.rstrip("/")
    url = f"{base}/health"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(url)
            ok = response.status_code == 200
            try:
                body = response.json()
            except Exception:
                body = {"raw": response.text[:200]}
            return {
                "reachable": ok,
                "status_code": response.status_code,
                "body": body,
            }
    except Exception as exc:
        return {
            "reachable": False,
            "status_code": None,
            "error": str(exc),
        }


async def get_arena_status(target_url: str) -> dict[str, Any]:
    stats = arena_app_stats()
    health = await arena_target_health(target_url)
    try:
        entry = resolved_arena_entry_basename()
        entry_error = None
    except RuntimeError as exc:
        entry = None
        entry_error = str(exc)
    return {
        "arena_source_dir": str(arena_source_dir()),
        "arena_entry_file": entry,
        "arena_entry_error": entry_error,
        "app_py": stats,
        "target_health": health,
    }
