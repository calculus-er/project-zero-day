"""
Arena (Tier 1) — path resolution and status for arena/source/app.py.
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


def arena_app_path() -> Path:
    return arena_source_dir() / "app.py"


def arena_app_stats() -> dict[str, Any]:
    path = arena_app_path()
    if not path.is_file():
        return {
            "exists": False,
            "path": str(path),
            "size_bytes": None,
            "modified_utc": None,
        }
    stat = path.stat()
    return {
        "exists": True,
        "path": str(path),
        "size_bytes": stat.st_size,
        "modified_utc": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
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
    return {
        "arena_source_dir": str(arena_source_dir()),
        "app_py": stats,
        "target_health": health,
    }
