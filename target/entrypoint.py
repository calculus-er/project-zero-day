"""Resolve ARENA_ENTRY_FILE (including ``auto``), optional incoming→app.py sync, then exec."""
from __future__ import annotations

import importlib.util
import glob
import os
import sys


def _load_incoming_sync():
    spec = importlib.util.spec_from_file_location("incoming_sync", "/incoming_sync.py")
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _pick_auto() -> str:
    files = sorted(
        os.path.basename(p)
        for p in glob.glob("/app/*.py")
        if os.path.isfile(p) and not os.path.basename(p).startswith("app.bak.")
    )
    if len(files) == 1:
        return files[0]
    print(
        f"[entrypoint] ARENA_ENTRY_FILE=auto needs exactly one .py in /app (found {files!r}); "
        "falling back to app.py",
        file=sys.stderr,
    )
    return "app.py"


def main() -> None:
    mod = _load_incoming_sync()
    if mod is not None:
        res = mod.apply_incoming_sync("/incoming", "/app/app.py")
        if res.get("did_sync"):
            print(f"[entrypoint] incoming → app.py: {res.get('from')}", file=sys.stderr)

    os.chdir("/app")
    raw = (os.environ.get("ARENA_ENTRY_FILE") or "app.py").strip()
    if raw.lower() == "auto":
        raw = _pick_auto()
    if not raw.endswith(".py"):
        raw = f"{raw}.py"
    os.execvp("python", ["python", raw])


if __name__ == "__main__":
    main()
