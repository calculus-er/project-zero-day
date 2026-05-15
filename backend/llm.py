import asyncio
import os
import time
from typing import Optional

from groq import Groq

# llama-3.1-70b-versatile and mixtral-8x7b-32768 are decommissioned on Groq
DEFAULT_PRIMARY = "llama-3.3-70b-versatile"
DEFAULT_FALLBACK = "llama-3.1-8b-instant"

PRIMARY_MODEL = os.getenv("GROQ_MODEL_PRIMARY", DEFAULT_PRIMARY)
FALLBACK_MODEL = os.getenv("GROQ_MODEL_FALLBACK", DEFAULT_FALLBACK)

MIN_DELAY_SECONDS = float(os.getenv("GROQ_MIN_DELAY_SECONDS", "2.0"))
MAX_RETRIES = 5

_client: Optional[Groq] = None
_last_call_at: float = 0.0
_rate_lock = asyncio.Lock()


def _get_client() -> Groq:
    global _client
    if _client is None:
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise RuntimeError("GROQ_API_KEY is not set in .env")
        _client = Groq(api_key=api_key)
    return _client


async def _enforce_rate_limit() -> None:
    global _last_call_at
    async with _rate_lock:
        elapsed = time.monotonic() - _last_call_at
        if elapsed < MIN_DELAY_SECONDS:
            await asyncio.sleep(MIN_DELAY_SECONDS - elapsed)
        _last_call_at = time.monotonic()


def _sync_chat(system_prompt: str, user_prompt: str, model: str) -> str:
    client = _get_client()
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.4,
        max_tokens=1024,
    )
    return (response.choices[0].message.content or "").strip()


def _should_try_fallback(exc: Exception) -> bool:
    text = str(exc).lower()
    return any(
        token in text
        for token in (
            "model_decommissioned",
            "decommissioned",
            "does not exist",
            "model_not_found",
            "invalid_request_error",
        )
    )


def _is_rate_limited(exc: Exception) -> bool:
    text = str(exc).lower()
    return "429" in text or "rate" in text or "503" in text


async def groq_complete(system_prompt: str, user_prompt: str) -> str:
    """Groq chat with 2s spacing, backoff on rate limits, fallback model on 400s."""
    await _enforce_rate_limit()

    models = [PRIMARY_MODEL, FALLBACK_MODEL]
    last_error: Optional[Exception] = None

    for model in models:
        for attempt in range(MAX_RETRIES):
            try:
                return await asyncio.to_thread(
                    _sync_chat, system_prompt, user_prompt, model
                )
            except Exception as exc:
                last_error = exc
                if _should_try_fallback(exc):
                    break
                if _is_rate_limited(exc) and attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(min(2**attempt, 30))
                    continue
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(min(2**attempt, 10))
                    continue
                break

    raise RuntimeError(f"Groq API failed after retries: {last_error}")
