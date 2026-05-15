"""Safe read/write for arena/source/app.py (Phase 8D)."""

from __future__ import annotations

import ast
import shutil
from pathlib import Path

from arena_util import arena_app_path


def validate_python_source(source: str) -> None:
    tree = ast.parse(source)
    if not isinstance(tree, ast.Module):
        raise ValueError("not a module")


def backup_arena_app(scan_id: str) -> Path:
    app = arena_app_path()
    if not app.is_file():
        raise FileNotFoundError(f"arena app not found: {app}")
    bak = app.with_suffix(f".bak.{scan_id}")
    shutil.copy2(app, bak)
    return bak


def write_arena_app(source: str, scan_id: str) -> Path:
    validate_python_source(source)
    app = arena_app_path()
    app.parent.mkdir(parents=True, exist_ok=True)
    app.write_text(source, encoding="utf-8", newline="\n")
    return app


def read_arena_app() -> str:
    app = arena_app_path()
    return app.read_text(encoding="utf-8", errors="replace")
