"""
Build TargetProfile from arena/source/app.py — heuristics + Groq JSON (Phase 8B).
"""

from __future__ import annotations

import json
import re
from typing import Awaitable, Callable

from arena_util import arena_app_path
from llm import groq_complete
from target_intel import BREACH_SEEDS, DEFAULT_CMDI_MARKERS, DEFAULT_SQLI_MARKERS
from target_profile import EndpointSpec, TargetProfile, store_profile

BroadcastFn = Callable[[str, str, str], Awaitable[None]]


def _find_route_paths(source: str) -> list[tuple[str, str]]:
    """Return list of (path, decorator_suffix) from @app.route('/x', methods=[...])."""
    out: list[tuple[str, str]] = []
    for m in re.finditer(
        r'@app\.route\(\s*["\']([^"\']+)["\']([^)]*)\)',
        source,
    ):
        out.append((m.group(1), m.group(2)))
    return out


def _infer_injection_field_login(source: str) -> str:
    if re.search(r"data\.get\(\s*['\"]username['\"]", source):
        return "username"
    if re.search(r"data\.get\(\s*['\"]user['\"]", source):
        return "user"
    return "username"


def _pick_sqli_path(routes: list[tuple[str, str]], source: str) -> str:
    for path, _ in routes:
        pl = path.lower()
        if "login" in pl:
            return path if path.startswith("/") else f"/{path}"
    if "/login" in source:
        return "/login"
    for path, suf in routes:
        if "POST" in suf.upper() and "GET" not in suf.upper():
            return path if path.startswith("/") else f"/{path}"
    return "/login"


def _pick_cmdi_path(routes: list[tuple[str, str]], source: str) -> str:
    for path, _ in routes:
        if "ping" in path.lower():
            return path if path.startswith("/") else f"/{path}"
    if "/ping" in source:
        return "/ping"
    return "/ping"


def _fallback_profile(scan_id: str, vuln_type: str, source: str) -> TargetProfile:
    routes = _find_route_paths(source)
    vt = vuln_type.lower().strip()

    if vt == "cmdi":
        path = _pick_cmdi_path(routes, source)
        ep = EndpointSpec(
            path=path,
            method="POST",
            injection_field="host",
            fixed_json={},
            sink_summary="Heuristic: user input passed to shell (e.g. os.popen) for ping/host.",
            line_hint=None,
        )
        seeds = list(BREACH_SEEDS.get("cmdi", []))
        markers = list(DEFAULT_CMDI_MARKERS)
    else:
        path = _pick_sqli_path(routes, source)
        inj = _infer_injection_field_login(source)
        ep = EndpointSpec(
            path=path,
            method="POST",
            injection_field=inj,
            fixed_json={"password": "x"},
            sink_summary="Heuristic: string concatenation into SQL before cursor.execute.",
            line_hint=None,
        )
        seeds = list(BREACH_SEEDS.get("sqli", []))
        markers = list(DEFAULT_SQLI_MARKERS)

    text = _format_attack_surface(ep, vt, markers, seeds, degraded=True)
    return TargetProfile(
        scan_id=scan_id,
        vuln_type=vt,
        endpoint=ep,
        breach_markers=markers,
        seed_payloads=seeds,
        attack_surface_text=text,
        degraded=True,
    )


def _format_attack_surface(
    ep: EndpointSpec,
    vuln_type: str,
    markers: list[str],
    seeds: list[str],
    degraded: bool,
) -> str:
    body = {ep.injection_field: "<PAYLOAD>", **ep.fixed_json}
    flag = " (heuristic fallback — LLM analysis unavailable)" if degraded else ""
    return f"""
TARGET SOURCE ANALYSIS{flag}:
- Vulnerability focus: {vuln_type}
- HTTP: {ep.method} with JSON body shape: {json.dumps(body)}
- Path: {{base}}{ep.path}
- Sink: {ep.sink_summary}
- Success indicators in response body (substrings): {', '.join(markers[:8])}
- Example payloads to try: {', '.join(repr(s) for s in seeds[:4])}
- Output raw payload only for the "{ep.injection_field}" value — no URL form prefixes.
""".strip()


async def _llm_profile(
    source: str, vuln_type: str, scan_id: str, hints: str
) -> TargetProfile | None:
    vt = vuln_type.lower().strip()
    schema_hint = """
Return ONLY valid JSON (no markdown), shape:
{
  "path": "/login",
  "method": "POST",
  "injection_field": "username",
  "fixed_json": {"password": "x"},
  "sink_summary": "one sentence how user input reaches dangerous sink",
  "line_hint": 55,
  "breach_markers": ["admin", "success", "users"],
  "seed_payloads": ["' OR 1=1--", "admin'--"]
}
For cmdi: path like /ping, injection_field "host", fixed_json {} empty object,
seed_payloads like ["127.0.0.1 & echo HACKED"].
"""
    system = (
        "You are a security code analyst. The operator is scanning ONLY for "
        f"{vt} in this Flask app. Extract the JSON POST route and field used for "
        "injection, how the sink works, substrings that indicate AUTHENTIC success / "
        "command execution (from code and responses), and 4 short example payloads.\n"
        + schema_hint
    )
    user = f"File hints:\n{hints}\n\n--- app.py (truncated) ---\n{source[:12000]}"
    raw = await groq_complete(system, user)
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```\w*\n?", "", raw)
        raw = re.sub(r"\n?```$", "", raw)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None

    try:
        lh = data.get("line_hint")
        try:
            line_hint = int(lh) if lh is not None and lh != "" else None
        except (TypeError, ValueError):
            line_hint = None

        ep = EndpointSpec(
            path=str(data.get("path", "/login")).strip() or "/login",
            method=str(data.get("method", "POST")).strip().upper() or "POST",
            injection_field=str(
                data.get("injection_field", "username")
            ).strip(),
            fixed_json=dict(data.get("fixed_json") or {}),
            sink_summary=str(data.get("sink_summary", ""))[:500],
            line_hint=line_hint,
        )
        markers = [str(m) for m in (data.get("breach_markers") or []) if m]
        seeds = [str(s) for s in (data.get("seed_payloads") or []) if s]
        if not markers:
            markers = list(
                DEFAULT_CMDI_MARKERS if vt == "cmdi" else DEFAULT_SQLI_MARKERS
            )
        if not seeds:
            seeds = list(BREACH_SEEDS.get(vt, BREACH_SEEDS.get("sqli", [])))
        text = _format_attack_surface(ep, vt, markers, seeds, degraded=False)
        return TargetProfile(
            scan_id=scan_id,
            vuln_type=vt,
            endpoint=ep,
            breach_markers=markers,
            seed_payloads=seeds,
            attack_surface_text=text,
            degraded=False,
        )
    except Exception:
        return None


def _build_heuristic_hints(source: str, vuln_type: str) -> str:
    routes = _find_route_paths(source)
    route_lines = [f"{p} {s.strip()}" for p, s in routes[:12]]
    risky: list[str] = []
    for i, line in enumerate(source.splitlines(), start=1):
        ls = line.lower()
        if "cursor.execute" in ls and "+" in line:
            risky.append(f"line {i}: possible string-built SQL")
        if "popen" in ls or "shell=true" in ls:
            risky.append(f"line {i}: possible command injection sink")
    return (
        f"Declared routes ({len(routes)}):\n"
        + "\n".join(route_lines)
        + "\nRisky lines:\n"
        + "\n".join(risky[:15])
    )


async def analyze_and_store_profile(
    scan_id: str,
    vuln_type: str,
    broadcast_fn: BroadcastFn,
) -> TargetProfile:
    """Alpha phase-0: read arena app.py, LLM profile or heuristic fallback."""
    path = arena_app_path()
    if not path.is_file():
        await broadcast_fn(
            f"Alpha: arena app missing at {path} — using generic defaults",
            "ALPHA",
            "error",
        )
        prof = _fallback_profile(scan_id, vuln_type, "")
        store_profile(scan_id, prof)
        return prof

    source = path.read_text(encoding="utf-8", errors="replace")
    hints = _build_heuristic_hints(source, vuln_type)

    await broadcast_fn(
        "Alpha: Analyzing arena source (profile for this scan)...",
        "ALPHA",
        "thinking",
    )

    profile: TargetProfile | None = None
    try:
        profile = await _llm_profile(source, vuln_type, scan_id, hints)
    except Exception as exc:
        await broadcast_fn(
            f"Alpha: LLM profile failed ({exc}) — heuristic fallback",
            "ALPHA",
            "error",
        )

    if profile is None:
        profile = _fallback_profile(scan_id, vuln_type, source)
        await broadcast_fn(
            "Alpha: Using heuristic target profile (degraded=True)",
            "ALPHA",
            "info",
        )
    else:
        await broadcast_fn(
            f"Alpha: Profile OK → {profile.endpoint.method} {profile.endpoint.path} "
            f"field={profile.endpoint.injection_field}",
            "ALPHA",
            "success",
        )

    store_profile(scan_id, profile)
    return profile
