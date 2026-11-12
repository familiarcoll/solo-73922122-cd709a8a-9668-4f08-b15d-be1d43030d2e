"""Application configuration, all driven by environment variables.

Secrets (FERNET_KEY, DEMO_USER_PASSWORD) are supplied by the runtime
(see .env / docker-compose.yml) and are never logged.
"""
from __future__ import annotations

import os
from functools import lru_cache
from urllib.parse import quote

from cryptography.fernet import Fernet


class ConfigError(RuntimeError):
    pass


class Settings:
    def __init__(self) -> None:
        # Shared SQLite file. Every API process opens the same file and relies
        # on SQLite transactions + WAL so the two processes stay consistent.
        self.db_path: str = os.environ.get("AUTH_DB_PATH", "/data/auth.db")

        # 32 url-safe base64-encoded bytes, i.e. a Fernet key. Used to encrypt
        # the stored idempotent retry receipts. Provided by startup config.
        fernet_key = os.environ.get("FERNET_KEY", "").strip()
        if not fernet_key:
            raise ConfigError(
                "FERNET_KEY environment variable is required "
                "(generate one with: python -m cryptography.fernet)"
            )
        try:
            self.fernet = Fernet(fernet_key.encode("utf-8"))
        except (ValueError, TypeError) as exc:
            raise ConfigError(f"FERNET_KEY is not a valid Fernet key: {exc}") from None

        # Demo account credentials, overridable through the environment.
        self.demo_username: str = os.environ.get("DEMO_USERNAME", "demo")
        self.demo_password: str = os.environ.get("DEMO_USER_PASSWORD", "demo-pass-123")

        # Token lifetimes (seconds).
        self.access_ttl: int = int(os.environ.get("ACCESS_TOKEN_TTL", "60"))
        self.refresh_ttl: int = int(os.environ.get("REFRESH_TOKEN_TTL", "600"))
        # Idempotency window: a retry with the same (old refresh token,
        # request_id) returns the exact same token pair within this window.
        self.idempotency_ttl: int = int(os.environ.get("IDEMPOTENCY_TTL", "30"))

        # How long to keep rows around (consumed tokens / receipts / revoked
        # family markers) before the janitor may hard-delete them. Must be a
        # multiple of every TTL so live security state is never removed early.
        self.retention: int = int(
            os.environ.get("ROW_RETENTION", str(max(self.refresh_ttl, 3600)))
        )

    @property
    def sqlite_url(self) -> str:
        # quote so paths containing special chars stay valid
        return f"file:{quote(self.db_path)}?uri=true"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
