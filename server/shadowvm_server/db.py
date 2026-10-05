from __future__ import annotations

import datetime as dt

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Account(Base):
    __tablename__ = "accounts"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    api_token_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_now)
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)


class Loader(Base):
    __tablename__ = "loaders"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    k_hmac: Mapped[bytes] = mapped_column(LargeBinary)
    k_master: Mapped[bytes] = mapped_column(LargeBinary)
    k_sign_privkey_wrapped: Mapped[bytes] = mapped_column(LargeBinary)
    k_sign_pubkey: Mapped[bytes] = mapped_column(LargeBinary)
    build_sha256: Mapped[str] = mapped_column(String(64), default="")
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_now)
    owner_account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"))


class Blob(Base):
    __tablename__ = "blobs"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    loader_id: Mapped[str] = mapped_column(ForeignKey("loaders.id"))
    owner_account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"))
    sealed_body: Mapped[bytes] = mapped_column(LargeBinary)
    blob_sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_now)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class Challenge(Base):
    __tablename__ = "challenges"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    blob_id: Mapped[str] = mapped_column(ForeignKey("blobs.id"))
    loader_id: Mapped[str] = mapped_column(ForeignKey("loaders.id"))
    device_fp: Mapped[str] = mapped_column(String(128))
    nonce_c: Mapped[bytes] = mapped_column(LargeBinary)
    nonce_s: Mapped[bytes] = mapped_column(LargeBinary)
    deadline: Mapped[dt.datetime] = mapped_column(DateTime)
    consumed: Mapped[bool] = mapped_column(Boolean, default=False)


class Session(Base):
    __tablename__ = "sessions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    blob_id: Mapped[str] = mapped_column(ForeignKey("blobs.id"))
    loader_id: Mapped[str] = mapped_column(ForeignKey("loaders.id"))
    device_fp: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_now)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime, default=_now)
    actor: Mapped[str] = mapped_column(String(128), default="")
    action: Mapped[str] = mapped_column(String(64))
    meta_json: Mapped[str] = mapped_column(Text, default="")


_engine = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def init_engine(db_url: str):
    """Create and cache the async engine for the given db URL."""
    global _engine, _sessionmaker
    _engine = create_async_engine(db_url, future=True)
    _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False, class_=AsyncSession)
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    """Return the configured session factory."""
    if _sessionmaker is None:
        raise RuntimeError("db not initialized; call init_engine first")
    return _sessionmaker


async def create_all() -> None:
    """Create all tables in the current engine."""
    if _engine is None:
        raise RuntimeError("db not initialized")
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def drop_all() -> None:
    """Drop all tables (used by tests)."""
    if _engine is None:
        raise RuntimeError("db not initialized")
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


async def dispose() -> None:
    """Dispose the engine, releasing any open file handles."""
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None
