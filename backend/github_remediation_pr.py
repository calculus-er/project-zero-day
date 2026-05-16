"""
Phase 9 — open a GitHub pull request with remediated arena source (Contents API).
"""

from __future__ import annotations

import base64
import os
import re
from urllib.parse import quote
from typing import Any, Awaitable, Callable, Optional

import httpx

BroadcastFn = Callable[[str, str, str], Awaitable[None]]

GITHUB_API = "https://api.github.com"
API_VERSION = "2022-11-28"


def pr_enabled() -> bool:
    raw = os.getenv("GITHUB_PR_ENABLED", "").strip().lower()
    return raw in ("1", "true", "yes", "on")


def _headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
    }


def _parse_repo(spec: str) -> tuple[str, str]:
    s = spec.strip().rstrip("/")
    s = s.removeprefix("https://github.com/").removeprefix("http://github.com/")
    parts = [p for p in s.split("/") if p]
    if len(parts) >= 2:
        owner, repo = parts[0], parts[1].removesuffix(".git")
        return owner, repo
    raise ValueError(f"Invalid GITHUB_PR_REPO: {spec!r} (expected owner/repo)")


def _safe_branch(scan_id: str) -> str:
    core = re.sub(r"[^a-zA-Z0-9._-]+", "-", scan_id).strip("-")
    if not core:
        core = "scan"
    return f"remediation/{core[:72]}"


async def open_remediation_pr(
    scan_id: str,
    broadcast_fn: BroadcastFn,
    remediated_source: str,
    summary: str = "",
) -> dict[str, Any]:
    if not pr_enabled():
        return {"skipped": True}

    token = os.getenv("GITHUB_TOKEN", "").strip()
    repo_spec = os.getenv("GITHUB_PR_REPO", "").strip()
    base_branch = os.getenv("GITHUB_PR_BASE_BRANCH", "main").strip() or "main"
    file_path = os.getenv("GITHUB_PR_FILE_PATH", "app.py").strip() or "app.py"

    if not token or not repo_spec:
        await broadcast_fn(
            "Phase 9: GITHUB_PR_ENABLED but GITHUB_TOKEN or GITHUB_PR_REPO missing",
            "SYSTEM",
            "error",
        )
        return {"skipped": True, "error": "missing token or repo"}

    try:
        owner, repo = _parse_repo(repo_spec)
    except ValueError as exc:
        await broadcast_fn(f"Phase 9: {exc}", "SYSTEM", "error")
        return {"skipped": True, "error": str(exc)}

    branch = _safe_branch(scan_id)
    b64 = base64.b64encode(remediated_source.encode("utf-8")).decode("ascii")
    headers = _headers(token)

    async with httpx.AsyncClient(timeout=60.0) as client:
        ref_url = f"{GITHUB_API}/repos/{owner}/{repo}/git/ref/heads/{base_branch}"
        ref_res = await client.get(ref_url, headers=headers)
        if ref_res.status_code != 200:
            await broadcast_fn(
                f"Phase 9: cannot read ref heads/{base_branch} ({ref_res.status_code})",
                "SYSTEM",
                "error",
            )
            return {"error": ref_res.text[:500], "status": ref_res.status_code}

        base_sha = ref_res.json()["object"]["sha"]

        create_ref = await client.post(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/refs",
            headers=headers,
            json={"ref": f"refs/heads/{branch}", "sha": base_sha},
        )
        if create_ref.status_code not in (201, 422):
            await broadcast_fn(
                f"Phase 9: create branch failed ({create_ref.status_code})",
                "SYSTEM",
                "error",
            )
            return {"error": create_ref.text[:500]}
        if create_ref.status_code == 422:
            try:
                msg = create_ref.json().get("message", "")
            except Exception:
                msg = ""
            if msg and "already exists" not in msg.lower():
                await broadcast_fn(
                    f"Phase 9: create branch rejected — {msg}",
                    "SYSTEM",
                    "error",
                )
                return {"error": create_ref.text[:500]}

        contents_url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{quote(file_path)}"
        cur = await client.get(
            contents_url,
            headers=headers,
            params={"ref": branch},
        )
        file_sha: Optional[str] = None
        if cur.status_code == 200:
            file_sha = cur.json().get("sha")
        elif cur.status_code != 404:
            await broadcast_fn(
                f"Phase 9: cannot read {file_path} on branch ({cur.status_code})",
                "SYSTEM",
                "error",
            )
            return {"error": cur.text[:500]}

        body: dict[str, Any] = {
            "message": f"fix(security): Blue Swarm remediation (scan {scan_id[:8]})",
            "content": b64,
            "branch": branch,
        }
        if file_sha:
            body["sha"] = file_sha

        put_res = await client.put(contents_url, headers=headers, json=body)
        if put_res.status_code not in (200, 201):
            await broadcast_fn(
                f"Phase 9: commit file failed ({put_res.status_code})",
                "SYSTEM",
                "error",
            )
            return {"error": put_res.text[:500]}

        title = os.getenv(
            "GITHUB_PR_TITLE_PREFIX", "Security remediation (Blue Swarm)"
        ).strip()
        pr_title = f"{title} [{scan_id[:8]}]"

        pr_body = summary.strip() or (
            "Automated fix from **Project Zero-Day** Blue Swarm after confirmed breach.\n\n"
            f"- Scan id: `{scan_id}`\n"
            f"- Branch: `{branch}`\n"
        )

        pr_res = await client.post(
            f"{GITHUB_API}/repos/{owner}/{repo}/pulls",
            headers=headers,
            json={
                "title": pr_title,
                "head": branch,
                "base": base_branch,
                "body": pr_body,
                "maintainer_can_modify": True,
            },
        )
        if pr_res.status_code != 201:
            await broadcast_fn(
                f"Phase 9: open PR failed ({pr_res.status_code}) — branch {branch} exists with commit",
                "SYSTEM",
                "error",
            )
            return {"error": pr_res.text[:500], "branch": branch}

        data = pr_res.json()
        html_url = data.get("html_url", "")
        await broadcast_fn(f"Phase 9: opened PR {html_url}", "SYSTEM", "success")
        return {"url": html_url, "branch": branch, "number": data.get("number")}
