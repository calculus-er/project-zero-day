import difflib
import os
from typing import Any, Awaitable, Callable, Optional

from arena_patch_llm import llm_rewrite_arena
from patch_apply import backup_arena_app, read_arena_app, validate_python_source, write_arena_app
from patch_templates import build_remediation
from template_remediate import apply_template_remediation
from arena_util import arena_app_path

BroadcastFn = Callable[[str, str, str], Awaitable[None]]

FALLBACK_BANNER = (
    "[FALLBACK] LLM patch failed — applied deterministic template fixes to the arena file."
)


async def run_epsilon(
    scan_id: str,
    vuln_type: str,
    winning_payload: str,
    delta_result: dict[str, Any],
    broadcast_fn: BroadcastFn,
    workflow_id: str = "",
    parent_span_id: Optional[str] = None,
) -> dict[str, Any]:
    diagnosis = delta_result.get("diagnosis", "")
    template_meta = build_remediation(vuln_type, winning_payload)

    await broadcast_fn(
        "Epsilon: Backing up arena/source/app.py and attempting LLM rewrite…",
        "EPSILON",
        "thinking",
    )

    original = read_arena_app()
    backup_arena_app(scan_id)

    used_fallback = False
    new_source: str | None = None
    fix_summary = ""

    try:
        candidate = await llm_rewrite_arena(
            original, vuln_type, diagnosis, winning_payload
        )
        if candidate:
            try:
                validate_python_source(candidate)
                new_source = candidate
                fix_summary = (
                    "LLM rewrote arena/source/app.py (parameterized SQL or safe subprocess). "
                    "Restart Docker target to load changes."
                )
            except SyntaxError:
                new_source = None
    except Exception as exc:
        await broadcast_fn(
            f"Epsilon: LLM rewrite error — {exc}",
            "EPSILON",
            "error",
        )
        new_source = None

    if new_source is None:
        used_fallback = True
        await broadcast_fn(FALLBACK_BANNER, "EPSILON", "error")
        tpl_text, tpl_note = apply_template_remediation(vuln_type, original)
        if tpl_text is None:
            raise RuntimeError(
                f"LLM and template remediation failed ({tpl_note}). "
                "Restore from backup .bak file if needed."
            )
        try:
            validate_python_source(tpl_text)
            new_source = tpl_text
        except SyntaxError as exc:
            raise RuntimeError(f"Template remediation produced invalid Python: {exc}") from exc

        fix_summary = (
            f"{FALLBACK_BANNER} ({tpl_note}). "
            f"{template_meta['fix_summary']} Restart Docker target."
        )

    assert new_source is not None
    write_arena_app(new_source, scan_id)

    diff_lines = list(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            new_source.splitlines(keepends=True),
            fromfile="arena/source/app.py (before)",
            tofile="arena/source/app.py (after)",
        )
    )
    diff_text = "".join(diff_lines)
    if len(diff_text) > 12000:
        diff_text = diff_text[:12000] + "\n... (truncated)\n"

    filename = f"{scan_id}_{template_meta['filename']}"
    export_header = (
        f"# Project Zero-Day — Blue Swarm remediation\n"
        f"# Scan: {scan_id}\n"
        f"# Vuln: {vuln_type} | CWE: {template_meta['cwe']}\n"
    )
    if used_fallback:
        export_header += f"# {FALLBACK_BANNER}\n"
    export_header += (
        f"# Payload: {winning_payload}\n#\n# {diagnosis}\n#\n"
        f"{template_meta['diff_preview']}\n\n--- unified diff (applied) ---\n{diff_text}"
    )

    patch_path = write_patch(filename, export_header)

    await broadcast_fn(
        f"Epsilon: arena/source/app.py updated — export: logs/patches/{filename}",
        "EPSILON",
        "success",
    )

    return {
        "patch_path": patch_path,
        "patch_filename": filename,
        "diff_preview": diff_text or template_meta["diff_preview"],
        "fix_summary": fix_summary,
        "patches_dir": os.path.normpath(PATCHES_DIR),
        "used_template_fallback": used_fallback,
        "arena_source_path": str(arena_app_path()),
    }
