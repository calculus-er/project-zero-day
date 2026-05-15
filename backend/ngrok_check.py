import os
from typing import Any

import httpx

NGROK_API = os.getenv("NGROK_API_URL", "http://127.0.0.1:4040/api/tunnels")
BACKEND_PORT = os.getenv("BACKEND_PORT", "8000")


async def get_ngrok_status() -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            response = await client.get(NGROK_API)
            response.raise_for_status()
            data = response.json()
    except Exception:
        return {
            "ngrok_connected": False,
            "public_url": None,
            "webhook_url": None,
        }

    for tunnel in data.get("tunnels", []):
        public_url = tunnel.get("public_url", "")
        addr = str(tunnel.get("config", {}).get("addr", ""))
        if not public_url.startswith("https://"):
            continue
        if BACKEND_PORT in addr or "localhost:8000" in addr or "127.0.0.1:8000" in addr:
            webhook_url = f"{public_url.rstrip('/')}/webhook/github"
            return {
                "ngrok_connected": True,
                "public_url": public_url,
                "webhook_url": webhook_url,
            }

    return {
        "ngrok_connected": False,
        "public_url": None,
        "webhook_url": None,
    }
