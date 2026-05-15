import os
from typing import Any, Awaitable, Callable, Optional

from patch_templates import build_remediation
from tools.file_ops import PATCHES_DIR, write_patch

BroadcastFn = Callable[[str, str, str], Awaitable[None]]


async def run_epsilon(
    scan_id: str,
    vuln_type: str,
    winning_payload: str,
    delta_result: dict[str, Any],
    broadcast_fn: BroadcastFn,
    workflow_id: str = "",
    parent_span_id: Optional[str] = None,
) -> dict[str, Any]:
    template = build_remediation(vuln_type, winning_payload)
    filename = f"{scan_id}_{template['filename']}"

    patch_body = (
        f"# Project Zero-Day — Blue Swarm remediation\n"
        f"# Scan: {scan_id}\n"
        f"# Vuln: {vuln_type} | CWE: {template['cwe']}\n"
        f"# Payload: {winning_payload}\n"
        f"#\n"
        f"# {delta_result.get('diagnosis', '')}\n"
        f"#\n"
        f"{template['diff_preview']}\n"
    )

    if template.get("fixed_snippet"):
        patch_body += f"\n# --- suggested function body ---\n# {template['fixed_snippet']}\n"

    await broadcast_fn(
        f"Epsilon: Writing patch → logs/patches/{filename}",
        "EPSILON",
        "thinking",
    )

    patch_path = write_patch(filename, patch_body)

    await broadcast_fn(
        f"Epsilon: Patch ready — apply to {template['file_hint']} and rebuild Docker target",
        "EPSILON",
        "success",
    )

    return {
        "patch_path": patch_path,
        "patch_filename": filename,
        "diff_preview": template["diff_preview"],
        "fix_summary": template["fix_summary"],
        "patches_dir": os.path.normpath(PATCHES_DIR),
    }
