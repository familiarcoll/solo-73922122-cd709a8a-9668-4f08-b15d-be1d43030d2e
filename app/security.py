"""Cryptographic primitives.

* Refresh/access tokens are random opaque strings. Only their SHA-256 hashes
  are ever stored in SQLite; the raw token leaves the server only inside the
  HTTPS response body.
* Passwords are stored as PBKDF2-HMAC-SHA256 hashes with a per-user salt.
* Idempotent retry receipts (the original token pair) are stored encrypted
  with the Fernet key supplied via startup configuration.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os

from .config import get_settings

# PBKDF2 iteration count for the demo account password.
_PBKDF2_ITERATIONS = 240_000


def generate_token(nbytes: int = 32) -> str:
    """Return an opaque, URL-safe random token."""
    return base64.urlsafe_b64encode(os.urandom(nbytes)).rstrip(b"=").decode("ascii")


def hash_token(token: str) -> str:
    """SHA-256 hash of an opaque token, hex encoded.

    SHA-256 of 256 bits of CSPRNG entropy is effectively a keyed hash here:
    the token itself is the secret. Only the digest is persisted.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    """Return a self-describing PBKDF2 hash string: pbkdf2_sha256$iter$salt$hash."""
    if salt is None:
        salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS
    )
    return "pbkdf2_sha256${it}${salt}${hash}".format(
        it=_PBKDF2_ITERATIONS,
        salt=base64.b64encode(salt).decode("ascii"),
        hash=base64.b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations, salt_b64, hash_b64 = stored.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            base64.b64decode(salt_b64),
            int(iterations),
        )
        return hmac.compare_digest(digest, base64.b64decode(hash_b64))
    except (ValueError, TypeError):
        return False


def encrypt_receipt(payload: bytes) -> bytes:
    return get_settings().fernet.encrypt(payload)


def decrypt_receipt(token: bytes) -> bytes:
    return get_settings().fernet.decrypt(token)
