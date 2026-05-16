#!/usr/bin/env python3
"""
Phase 8F — Reset arena/source to a committed vulnerable sample: replace the arena
entry ``*.py`` (see ARENA_ENTRY_FILE / ``auto``), remove SQLite DB + Epsilon
backups, optionally restart Docker target.

Run from repo root:
  python scripts/swap_arena_sample.py
  python scripts/swap_arena_sample.py --dry-run
  python scripts/swap_arena_sample.py --restart
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def ensure_backend_import(root: Path) -> None:
    sys.path.insert(0, str(root / "backend"))
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv(root / ".env")
    load_dotenv(root / "backend" / ".env", override=True)


def default_sample_path(root: Path) -> Path:
    override = os.getenv("ARENA_RESET_SAMPLE", "").strip()
    if override:
        p = Path(override).expanduser()
        return p if p.is_absolute() else (root / p).resolve()
    return (root / "arena" / "samples" / "app.py").resolve()


def remove_matching(dir_path: Path, desc: str, predicate, dry_run: bool) -> int:
    n = 0
    if not dir_path.is_dir():
        return 0
    for child in sorted(dir_path.iterdir()):
        if not predicate(child):
            continue
        n += 1
        print(f"  remove {desc}: {child.name}")
        if not dry_run:
            child.unlink()
    return n


def docker_compose_restart(root: Path, service: str, dry_run: bool) -> int:
    cmd = ["docker", "compose", "restart", service]
    print(f"  run: {' '.join(cmd)} (cwd={root})")
    if dry_run:
        return 0
    proc = subprocess.run(
        cmd,
        cwd=str(root),
        text=True,
        timeout=120,
    )
    if proc.returncode != 0:
        print("  docker compose restart failed", file=sys.stderr)
    return proc.returncode


def main() -> int:
    root = repo_root()
    ensure_backend_import(root)
    from arena_util import arena_app_path

    parser = argparse.ArgumentParser(
        description="Swap arena entry .py to Tier-1 vulnerable sample and clean artifacts.",
    )
    parser.add_argument(
        "--sample",
        type=Path,
        default=None,
        help="Source .py file (default: arena/samples/app.py or ARENA_RESET_SAMPLE)",
    )
    parser.add_argument(
        "--no-clean-db",
        action="store_true",
        help="Keep arena/source/*.db files",
    )
    parser.add_argument(
        "--no-clean-backups",
        action="store_true",
        help="Keep Epsilon backup files (*.*bak.*)",
    )
    parser.add_argument(
        "--restart",
        action="store_true",
        help="Run `docker compose restart` for DOCKER_COMPOSE_SERVICE (default: target)",
    )
    parser.add_argument(
        "--service",
        default=os.getenv("DOCKER_COMPOSE_SERVICE", "target").strip() or "target",
        help="Compose service to restart with --restart",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print actions only",
    )
    args = parser.parse_args()

    sample = (args.sample.resolve() if args.sample else default_sample_path(root))
    try:
        dest_app = arena_app_path()
    except RuntimeError as exc:
        print(f"[swap] {exc}", file=sys.stderr)
        return 1
    dest_dir = dest_app.parent

    if not sample.is_file():
        print(f"Sample not found: {sample}", file=sys.stderr)
        return 1

    dest_dir.mkdir(parents=True, exist_ok=True)

    print(f"[swap] root     = {root}")
    print(f"[swap] sample   = {sample}")
    print(f"[swap] dest app = {dest_app}")

    if args.dry_run:
        print(f"  (dry-run) copy sample -> {dest_app.name}")
    else:
        shutil.copy2(sample, dest_app)
        print(f"  copied sample -> {dest_app.name}")

    if not args.no_clean_db:

        def is_db(p: Path) -> bool:
            return p.is_file() and p.suffix.lower() == ".db"

        removed_db = remove_matching(dest_dir, "db", is_db, args.dry_run)
        if removed_db == 0:
            print("  (no .db files to remove)")

    if not args.no_clean_backups:

        def is_bak(p: Path) -> bool:
            return p.is_file() and ".bak." in p.name

        removed_bak = remove_matching(dest_dir, "backup", is_bak, args.dry_run)
        if removed_bak == 0:
            print("  (no backup files to remove)")

    if args.restart:
        code = docker_compose_restart(root, args.service, args.dry_run)
        if code != 0 and not args.dry_run:
            return code

    print("[swap] done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
