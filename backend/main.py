import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parent
ROOT_DIR = BACKEND_DIR.parent

# Load .env BEFORE project imports so Omium/Groq keys are available at init
load_dotenv(ROOT_DIR / ".env")
load_dotenv(BACKEND_DIR / ".env", override=True)

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from journal import journal
from arena_util import get_arena_status
from ngrok_check import get_ngrok_status
from orchestrator import run_scan
from remediation import remediation
from tracing import ensure_initialized, get_active_execution_id, is_enabled as tracing_enabled
from webhook_utils import verify_github_signature
from demo_repo_sync import demo_sync_enabled_for_webhook, sync_demo_repo_to_arena
from github_remediation_pr import pr_enabled

ensure_initialized()

app = FastAPI(title="Project Zero-Day")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

connected_clients: list[WebSocket] = []
scan_state: dict[str, Any] = {"status": "idle", "scan_id": None}


def _demo_restart_target_after_sync() -> bool:
    raw = os.getenv("GITHUB_DEMO_RESTART_TARGET", "true").strip().lower()
    return raw in ("1", "true", "yes", "on")


async def send_update(message: str, agent: str, level: str) -> None:
    payload = {
        "agent": agent,
        "message": message,
        "level": level,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    dead: list[WebSocket] = []
    for client in connected_clients:
        try:
            await client.send_json(payload)
        except Exception:
            dead.append(client)
    for client in dead:
        if client in connected_clients:
            connected_clients.remove(client)


class ScanRequest(BaseModel):
    target_url: str
    vuln_type: str = "sqli"


async def _execute_scan(
    scan_id: str, target_url: str, vuln_type: str, trigger: str = "manual"
) -> None:
    scan_state["status"] = "running"
    scan_state["scan_id"] = scan_id
    remediation.reset()

    if trigger == "github_webhook":
        if demo_sync_enabled_for_webhook():
            await send_update(
                "Phase 9: cloning GITHUB_DEMO_REPO (git may take up to a few minutes; "
                "ensure GITHUB_TOKEN is set for private repos)…",
                "WEBHOOK",
                "thinking",
            )
            import asyncio

            try:
                clone_timeout = int(os.getenv("GITHUB_DEMO_CLONE_TIMEOUT", "120")) + 45
            except ValueError:
                clone_timeout = 165
            try:
                sync_result = await asyncio.wait_for(
                    asyncio.to_thread(sync_demo_repo_to_arena),
                    timeout=float(clone_timeout),
                )
            except asyncio.TimeoutError:
                await send_update(
                    "Phase 9: git clone timed out — check network, GITHUB_TOKEN, branch name, "
                    "and that `git` is on PATH.",
                    "WEBHOOK",
                    "error",
                )
                scan_state["status"] = "failed"
                return
            if not sync_result.get("ok"):
                await send_update(
                    f"Phase 9 demo sync failed: {sync_result.get('error', 'unknown')}",
                    "WEBHOOK",
                    "error",
                )
                scan_state["status"] = "failed"
                return
            msg = f"Phase 9: copied demo app → {sync_result.get('copied_to')}"
            hint = sync_result.get("hint") or ""
            if hint:
                msg += f" — {hint}"
            await send_update(msg, "WEBHOOK", "success")

            if _demo_restart_target_after_sync():
                await send_update(
                    "Phase 9: restarting Docker `target` so the container loads new app.py…",
                    "WEBHOOK",
                    "thinking",
                )
                from docker_target_restart import (
                    restart_target_container,
                    wait_target_healthy,
                )

                rr = await restart_target_container()
                if not rr["ok"]:
                    await send_update(
                        f"Phase 9: docker compose restart failed "
                        f"(exit {rr['returncode']}): {rr['output'][:400]}",
                        "WEBHOOK",
                        "error",
                    )
                else:
                    await send_update(
                        f"Phase 9: `docker compose restart {rr['service']}` OK — waiting for /health…",
                        "WEBHOOK",
                        "info",
                    )
                    health = await wait_target_healthy(target_url)
                    if health.get("ok"):
                        await send_update(
                            f"Phase 9: target healthy after {health['attempts']} /health check(s)",
                            "WEBHOOK",
                            "success",
                        )
                    else:
                        await send_update(
                            f"Phase 9: /health not OK after restart — {health.get('error', 'unknown')}",
                            "WEBHOOK",
                            "error",
                        )

    try:
        outcome = await run_scan(
            scan_id, target_url, vuln_type, send_update, journal, trigger=trigger
        )
        if outcome == "breached":
            scan_state["status"] = "breached"
        elif outcome == "failed":
            scan_state["status"] = "failed"
        elif scan_state["status"] == "running":
            scan_state["status"] = "idle"
    except Exception as exc:
        await send_update(f"Scan failed: {exc}", "SYSTEM", "error")
        scan_state["status"] = "failed"


def _start_scan(background_tasks: BackgroundTasks, target_url: str, vuln_type: str) -> dict:
    if scan_state["status"] == "running":
        return {"status": "already_running", "scan_id": scan_state["scan_id"]}

    scan_id = str(uuid.uuid4())
    scan_state["scan_id"] = scan_id
    background_tasks.add_task(_execute_scan, scan_id, target_url, vuln_type, "manual")
    return {"status": "started", "scan_id": scan_id}


@app.get("/arena/status")
async def arena_status():
    target_url = os.getenv("TARGET_URL", "http://localhost:5000")
    return await get_arena_status(target_url)


@app.get("/webhook/status")
async def webhook_status():
    ngrok = await get_ngrok_status()
    return {
        **ngrok,
        "github_secret_configured": bool(os.getenv("GITHUB_WEBHOOK_SECRET")),
        "demo_sync_on_webhook": demo_sync_enabled_for_webhook(),
        "github_pr_enabled": pr_enabled(),
    }


@app.get("/status")
async def get_status():
    ngrok = await get_ngrok_status()
    return {
        "status": scan_state["status"],
        "scan_id": scan_state["scan_id"],
        "ngrok_connected": ngrok["ngrok_connected"],
        "omium_tracing": tracing_enabled(),
        "omium_execution_id": get_active_execution_id(),
        "remediation_status": remediation.to_dict().get("status", "idle"),
    }


@app.get("/remediation")
async def get_remediation():
    return remediation.to_dict()


@app.get("/journal")
async def get_journal():
    return {"entries": journal.get_entries()}


@app.post("/scan")
async def start_scan(body: ScanRequest, background_tasks: BackgroundTasks):
    return _start_scan(background_tasks, body.target_url, body.vuln_type)


@app.post("/webhook/github")
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    event = request.headers.get("X-GitHub-Event", "")
    body = await request.body()

    if event == "ping":
        return {"status": "pong"}

    if event != "push":
        return {"status": "ignored", "reason": "not a push event"}

    secret = os.getenv("GITHUB_WEBHOOK_SECRET", "")
    signature = request.headers.get("X-Hub-Signature-256")
    if not verify_github_signature(body, signature, secret):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    payload = json.loads(body)
    repo_name = payload.get("repository", {}).get("name", "unknown")
    pusher = payload.get("pusher", {}).get("name", "unknown")
    ref = payload.get("ref", "") or ""
    branch = ref.replace("refs/heads/", "") if ref.startswith("refs/heads/") else ref

    # Phase 9 PRs push branch remediation/<scan-id> → GitHub fires another push webhook.
    # Syncing again would re-copy main's app.py over the local patch and wipe remediation UI.
    if branch.startswith("remediation/"):
        return {
            "status": "ignored",
            "reason": "remediation/* branch (automated PR fix — prevents sync/scan loop)",
        }

    allow = os.getenv("GITHUB_WEBHOOK_ONLY_BRANCHES", "").strip()
    if allow:
        allowed = {b.strip() for b in allow.split(",") if b.strip()}
        if branch not in allowed:
            return {
                "status": "ignored",
                "reason": f"branch {branch!r} not in GITHUB_WEBHOOK_ONLY_BRANCHES",
            }

    target_url = os.getenv("TARGET_URL", "http://localhost:5000")
    vuln_type = os.getenv("DEFAULT_VULN_TYPE", "sqli")

    await send_update(
        f"GitHub push from {pusher} on {repo_name} ({branch}) — auto-scan triggered",
        "WEBHOOK",
        "info",
    )

    scan_id = str(uuid.uuid4())
    if scan_state["status"] == "running":
        return {"status": "already_running", "scan_id": scan_state["scan_id"]}

    scan_state["scan_id"] = scan_id
    background_tasks.add_task(
        _execute_scan, scan_id, target_url, vuln_type, "github_webhook"
    )
    return {"status": "accepted", "scan_id": scan_id, "started": True}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    await send_update("WebSocket client connected", "SYSTEM", "info")
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in connected_clients:
            connected_clients.remove(websocket)


@app.get("/")
async def root():
    return {"service": "Project Zero-Day", "status": scan_state["status"]}
