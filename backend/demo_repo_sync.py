"""
Phase 9 — shallow-clone a GitHub demo repo and copy a chosen file into arena/source.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import uuid
from pathlib import Path
from typing import Any

from arena_util import ROOT_DIR, arena_source_dir

DEMO_CLONE_ROOT = ROOT_DIR / ".demo_repos"


def _rmtree_best_effort(path: Path) -> None:
    """Windows often locks ``.git/objects/pack``; chmod + retry avoids most failures."""

    def _onerror(func: Any, p: str, _exc_info: Any) -> None:
        try:
            os.chmod(p, stat.S_IWUSR | stat.S_IREAD | stat.S_IEXEC)
            func(p)
        except Exception:
            pass

    if path.exists():
        shutil.rmtree(path, onerror=_onerror)


def demo_sync_enabled_for_webhook() -> bool:
    raw = os.getenv("GITHUB_DEMO_SYNC_ON_WEBHOOK", "").strip().lower()
    return raw in ("1", "true", "yes", "on")


def _safe_dirname(repo: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9._-]+", "_", repo.replace("/", "__"))
    return s[:120] or "repo"


def _clone_url(repo: str, token: str) -> str:
    r = repo.strip().rstrip("/")
    if r.startswith("http://") or r.startswith("https://"):
        return r
    if "/" not in r:
        raise ValueError("GITHUB_DEMO_REPO must be owner/name or a https clone URL")
    owner, name = r.split("/", 1)
    name = name.removesuffix(".git")
    if token:
        return f"https://x-access-token:{token}@github.com/{owner}/{name}.git"
    return f"https://github.com/{owner}/{name}.git"


def sync_demo_repo_to_arena() -> dict[str, Any]:
    """
    Clone GITHUB_DEMO_REPO (branch GITHUB_DEMO_BRANCH) and copy
    DEMO_APP_RELATIVE_PATH into arena (filename preserved).
    """
    repo = os.getenv("GITHUB_DEMO_REPO", "").strip()
    if not repo:
        return {"ok": False, "error": "GITHUB_DEMO_REPO is not set"}
    branch = os.getenv("GITHUB_DEMO_BRANCH", "main").strip() or "main"
    rel = os.getenv("DEMO_APP_RELATIVE_PATH", "app.py").strip() or "app.py"
    token = os.getenv("GITHUB_TOKEN", "").strip()

    try:
        url = _clone_url(repo, token)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    # Fresh path every run — never ``rmtree`` a stable-named previous clone on Windows
    # (``.git`` pack files are often locked → PermissionError).
    base = _safe_dirname(repo)
    clone_dir = DEMO_CLONE_ROOT / f"{base}__{uuid.uuid4().hex[:12]}"
    DEMO_CLONE_ROOT.mkdir(parents=True, exist_ok=True)

    try:
        timeout_s = int(os.getenv("GITHUB_DEMO_CLONE_TIMEOUT", "120"))
    except ValueError:
        timeout_s = 120
    clone_env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    try:
        subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--single-branch",
                "-b",
                branch,
                url,
                str(clone_dir),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            env=clone_env,
        )
    except FileNotFoundError:
        return {"ok": False, "error": "git executable not found on PATH"}
    except subprocess.CalledProcessError as exc:
        err = (exc.stderr or exc.stdout or "").strip()[:800]
        _rmtree_best_effort(clone_dir)
        return {"ok": False, "error": f"git clone failed: {err}"}
    except (OSError, subprocess.TimeoutExpired) as exc:
        _rmtree_best_effort(clone_dir)
        return {"ok": False, "error": str(exc)}

    src = (clone_dir / rel).resolve()
    if not src.is_file():
        _rmtree_best_effort(clone_dir)
        return {"ok": False, "error": f"cloned repo has no file at {rel!r}"}

    arena_dir = arena_source_dir()
    arena_dir.mkdir(parents=True, exist_ok=True)

    exclusive = os.getenv("GITHUB_DEMO_EXCLUSIVE_SYNC", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )
    if exclusive:
        for p in arena_dir.glob("*.py"):
            if p.name.startswith("app.bak."):
                continue
            p.unlink()

    dest = arena_dir / Path(rel).name
    shutil.copy2(src, dest)

    _rmtree_best_effort(clone_dir)

    hint = ""
    entry = os.getenv("ARENA_ENTRY_FILE", "app.py").strip() or "app.py"
    if entry.lower() == "auto":
        hint = " ARENA_ENTRY_FILE=auto will run this file if it is the only .py in arena/source."
    elif Path(entry).name != dest.name:
        hint = (
            f" Set ARENA_ENTRY_FILE={dest.name} (or auto with only this .py) "
            f"so Docker and Blue Swarm patch the same file."
        )

    return {
        "ok": True,
        "copied_to": str(dest),
        "clone_dir": str(clone_dir),
        "hint": hint.strip(),
    }
