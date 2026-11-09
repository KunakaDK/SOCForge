from __future__ import annotations

import hashlib
import hmac


def sign_payload(raw_body: bytes, secret: str) -> str:
    """Return an HMAC-SHA256 signature for an exact HTTP request body."""
    return hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()


def verify_payload(raw_body: bytes, supplied_signature: str | None, secret: str) -> bool:
    if not supplied_signature:
        return False
    expected = sign_payload(raw_body, secret)
    candidate = supplied_signature.removeprefix("sha256=").strip()
    return hmac.compare_digest(expected, candidate)
