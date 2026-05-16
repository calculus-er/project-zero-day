#!/usr/bin/env python3
"""
Copy ``arena/incoming/<any>.py`` → ``arena/source/app.py`` so Docker and Blue Swarm
always use ``app.py`` without renaming your test file.

  python scripts/sync_incoming_to_app.py
  python scripts/sync_incoming_to_app.py --dry-run

Optional: set ARENA_INCOMING_FILE=mything.py when multiple ``*.py`` exist in incoming.
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def load_sync_mod(root: Path):
    path = root / "target" / "incoming_sync.py"
    spec = importlib.util.spec_from_file_location("incoming_sync", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show which file would be copied only",
    )
    args = parser.parse_args()

    root = repo_root()
    import os

    rel_in = os.getenv("ARENA_INCOMING_DIR", "arena/incoming").strip()
    p_in = Path(rel_in)
    incoming = p_in if p_in.is_absolute() else (root / p_in).resolve()

    rel_src = os.getenv("ARENA_SOURCE_DIR", "arena/source").strip()
    p_src = Path(rel_src)
    source_dir = p_src if p_src.is_absolute() else (root / p_src).resolve()
    app_py = source_dir / "app.py"

    mod = load_sync_mod(root)

    if args.dry_run:
        specific = (os.environ.get("ARENA_INCOMING_FILE") or "").strip()
        py_files = sorted(p for p in incoming.glob("*.py") if p.is_file())
        if specific:
            src = incoming / Path(specific).name
            print(f"[dry-run] would copy {src} -> {app_py}")
            return 0 if src.is_file() else 1
        if len(py_files) == 1:
            print(f"[dry-run] would copy {py_files[0]} -> {app_py}")
            return 0
        print(f"[dry-run] incoming .py files: {[p.name for p in py_files]}", file=sys.stderr)
        return 1

    res = mod.apply_incoming_sync(incoming, app_py, force=True)
    if not res.get("did_sync"):
        print(res.get("error", res.get("reason", "sync failed")), file=sys.stderr)
        return 1
    print(f"Copied {res.get('from')} → {res.get('to')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
