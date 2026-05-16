"""
Copy one arbitrary ``*.py`` from an "incoming" folder into ``app.py``.

Used by ``target/entrypoint.py`` (Docker) and ``scripts/sync_incoming_to_app.py`` (host).
Canonical target path is always ``app.py`` — no ARENA_ENTRY_FILE changes needed.
"""

from __future__ import annotations

import glob
import os
import shutil
import sys
from pathlib import Path


def _truthy(val: str | None) -> bool:
    if not val:
        return False
    return val.strip().lower() in ("1", "true", "yes", "on")


def apply_incoming_sync(
    incoming_dir: str | Path,
    app_py: str | Path,
    *,
    incoming_file: str | None = None,
    force: bool = False,
) -> dict[str, object]:
    """
    If ``force`` or env ``ARENA_INCOMING_SYNC`` is truthy: copy one ``.py`` from
    ``incoming_dir`` onto ``app_py``.

    - If ``incoming_file`` or env ``ARENA_INCOMING_FILE`` is set (basename only),
      copy that file.
    - Else require exactly one ``*.py`` in ``incoming_dir`` (non-recursive).
    """
    env_sync = _truthy(os.environ.get("ARENA_INCOMING_SYNC"))
    if not force and not env_sync:
        return {"did_sync": False, "reason": "ARENA_INCOMING_SYNC not enabled"}

    inc = Path(incoming_dir)
    dst = Path(app_py)
    specific = (incoming_file or os.environ.get("ARENA_INCOMING_FILE") or "").strip()
    if specific:
        specific = Path(specific).name
        src = inc / specific
        if not src.is_file():
            msg = f"ARENA_INCOMING_FILE not found: {src}"
            print(f"[incoming_sync] {msg}", file=sys.stderr)
            return {"did_sync": False, "error": msg}
        shutil.copy2(src, dst)
        return {"did_sync": True, "from": str(src), "to": str(dst)}

    py_files = sorted(p for p in inc.glob("*.py") if p.is_file())
    if len(py_files) == 0:
        msg = "no .py files in incoming dir"
        print(f"[incoming_sync] {msg}", file=sys.stderr)
        return {"did_sync": False, "error": msg}
    if len(py_files) > 1:
        names = [p.name for p in py_files]
        msg = (
            f"multiple .py in incoming ({names}); set ARENA_INCOMING_FILE=basename.py "
            "or leave only one file"
        )
        print(f"[incoming_sync] {msg}", file=sys.stderr)
        return {"did_sync": False, "error": msg}

    shutil.copy2(py_files[0], dst)
    return {"did_sync": True, "from": str(py_files[0]), "to": str(dst)}
