from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Config:
    """Runtime configuration loaded from environment variables."""
    db_url: str
    kms_backend: str
    kms_keyring: str
    listen: str
    tls_cert: str | None
    tls_key: str | None
    rate_compile_per_hour: int
    rate_session_per_hour: int
    rate_blob_fetch_per_hour: int
    session_ttl_ms: int


def _load_dotenv(path: str) -> None:
    p = Path(path)
    if not p.exists():
        return
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = val


def load(env_file: str | None = None) -> Config:
    """Load configuration from environment, optionally seeding from a .env file."""
    if env_file:
        _load_dotenv(env_file)
    else:
        default_env = Path.cwd() / ".env"
        if default_env.exists():
            _load_dotenv(str(default_env))
    return Config(
        db_url=os.environ.get("SHADOWVM_DB_URL", "sqlite+aiosqlite:///./shadowvm.db"),
        kms_backend=os.environ.get("SHADOWVM_KMS_BACKEND", "file"),
        kms_keyring=os.environ.get("SHADOWVM_KMS_KEYRING", "./keyring.json"),
        listen=os.environ.get("SHADOWVM_LISTEN", "0.0.0.0:8443"),
        tls_cert=os.environ.get("SHADOWVM_TLS_CERT") or None,
        tls_key=os.environ.get("SHADOWVM_TLS_KEY") or None,
        rate_compile_per_hour=int(os.environ.get("SHADOWVM_RATE_COMPILE_PER_HOUR", "60")),
        rate_session_per_hour=int(os.environ.get("SHADOWVM_RATE_SESSION_PER_HOUR", "600")),
        rate_blob_fetch_per_hour=int(os.environ.get("SHADOWVM_RATE_BLOB_FETCH_PER_HOUR", "3600")),
        session_ttl_ms=int(os.environ.get("SHADOWVM_SESSION_TTL_MS", "600000")),
    )
