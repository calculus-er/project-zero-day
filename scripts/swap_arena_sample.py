#!/usr/bin/env python3
"""
Phase 8F — Reset arena/source to a committed vulnerable sample: replace app.py,
remove SQLite DB + Epsilon backups, optionally restart Docker target.

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


def default_sample_path(root: Path) -> Path:
    override = os.getenv("ARENA_RESET_SAMPLE", "").strip()
    if override:
        p = Path(override).expanduser()
        return p if p.is_absolute() else (root / p).resolve()
    return (root / "arena" / "samples" / "tier1_vulnerable_app.py").resolve()


def arena_source_dir(root: Path) -> Path:
    rel = os.getenv("ARENA_SOURCE_DIR", "arena/source").strip()
    p = Path(rel)
    return p.resolve() if p.is_absolute() else (root / p).resolve()


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
    parser = argparse.ArgumentParser(
        description="Swap arena/source/app.py to Tier-1 vulnerable sample and clean artifacts.",
    )
    parser.add_argument(
        "--sample",
        type=Path,
        default=None,
        help="Source .py file (default: arena/samples/tier1_vulnerable_app.py or ARENA_RESET_SAMPLE)",
    )
    parser.add_argument(
        "--no-clean-db",
        action="store_true",
        help="Keep arena/source/*.db files",
    )
    parser.add_argument(
        "--no-clean-backups",
        action="store_true",
        help="Keep arena/source/app.bak.* from Epsilon",
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

    root = repo_root()
    sample = (args.sample.resolve() if args.sample else default_sample_path(root))
    dest_dir = arena_source_dir(root)
    dest_app = dest_dir / "app.py"

    if not sample.is_file():
        print(f"Sample not found: {sample}", file=sys.stderr)
        return 1

    dest_dir.mkdir(parents=True, exist_ok=True)

    print(f"[swap] root        = {root}")
    print(f"[swap] sample      = {sample}")
    print(f"[swap] dest app.py = {dest_app}")

    if args.dry_run:
        print("  (dry-run) copy sample -> app.py")
    else:
        shutil.copy2(sample, dest_app)
        print("  copied sample -> app.py")

    removed_db = 0
    if not args.no_clean_db:

        def is_db(p: Path) -> bool:
            return p.is_file() and p.suffix.lower() == ".db"

        removed_db = remove_matching(dest_dir, "db", is_db, args.dry_run)
        if removed_db == 0:
            print("  (no .db files to remove)")

    removed_bak = 0
    if not args.no_clean_backups:

        def is_bak(p: Path) -> bool:
            return p.is_file() and p.name.startswith("app.bak.")

        removed_bak = remove_matching(dest_dir, "backup", is_bak, args.dry_run)
        if removed_bak == 0:
            print("  (no app.bak.* to remove)")

    if args.restart:
        code = docker_compose_restart(root, args.service, args.dry_run)
        if code != 0 and not args.dry_run:
            return code

    print("[swap] done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
