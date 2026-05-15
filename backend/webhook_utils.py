import hashlib
import hmac
from typing import Optional


def verify_github_signature(
    payload_body: bytes, signature_header: Optional[str], secret: str
) -> bool:
    if not secret:
        return False
    if not signature_header:
        return False

    received = signature_header
    if received.startswith("sha256="):
        received = received[7:]

    expected = hmac.new(
        secret.encode("utf-8"), payload_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(received, expected)
