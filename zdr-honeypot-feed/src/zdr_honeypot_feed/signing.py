"""HMAC-SHA256 signing of the JSON feed.

Consumers verify the `X-ZDR-Signature` header against the response body using
the shared key. Any CDN or MITM tampering breaks the signature.
"""

from __future__ import annotations

import hashlib
import hmac


def sign(body: bytes, key: str) -> str:
    mac = hmac.new(key.encode("utf-8"), body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def verify(body: bytes, signature: str, key: str) -> bool:
    expected = sign(body, key)
    return hmac.compare_digest(expected, signature)
