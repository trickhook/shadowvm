from __future__ import annotations

import base64
import datetime as dt
import hmac
import json
import os
import secrets
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from shadowc.crypto import blake2s, xchacha20, poly1305

from . import compile as compiler
from .auth import check_rate, rate_limiter, require_account
from .config import Config, load as load_config
from .db import (
    Account,
    Blob,
    Challenge,
    Loader,
    Session as SessionRow,
    create_all,
    get_sessionmaker,
    init_engine,
)
from .kms import KMS, build_kms


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _ms(ts: dt.datetime) -> int:
    return int(ts.timestamp() * 1000)


def _rid(prefix: str, n: int = 8) -> str:
    return f"{prefix}_{secrets.token_hex(n)}"


class CompileRequest(BaseModel):
    source: str
    target_loader_id: str
    symbols: list[str] | None = None
    flags: dict[str, Any] | None = None


class CompileResponse(BaseModel):
    blob_id: str
    blob_sha256: str
    sealed_blob: str
    created_at: int


class IntegrityResponse(BaseModel):
    ok: bool
    blob_sha256: str
    verified_at: int


class ChallengeRequest(BaseModel):
    blob_id: str
    loader_id: str
    device_fp: str
    nonce_c: str = Field(..., description="hex-encoded 16 bytes")


class ChallengeResponse(BaseModel):
    challenge_id: str
    nonce_s: str
    ttl_ms: int


class CompleteRequest(BaseModel):
    challenge_id: str
    proof: str


class CompleteResponse(BaseModel):
    session_id: str
    envelope_sealed: str
    envelope_sig: str
    expires: int


def create_app(config: Config | None = None, kms: KMS | None = None) -> FastAPI:
    """Build and wire the FastAPI application."""
    cfg = config or load_config()

    @asynccontextmanager
    async def _lifespan(app: FastAPI):
        init_engine(cfg.db_url)
        await create_all()
        if app.state.kms is None:
            app.state.kms = build_kms(cfg.kms_backend, cfg.kms_keyring)
        yield

    app = FastAPI(title="shadowvm-server", version="0.1.0", lifespan=_lifespan)
    app.state.config = cfg
    app.state.kms = kms

    @app.get("/v1/health")
    async def health():
        return {"ok": True}

    @app.post("/v1/compile", response_model=CompileResponse)
    async def compile_endpoint(
        body: CompileRequest,
        account: Account = Depends(require_account),
    ):
        check_rate(account.id, "compile", cfg.rate_compile_per_hour)
        sm = get_sessionmaker()
        async with sm() as sess:
            loader = (await sess.execute(
                select(Loader).where(Loader.id == body.target_loader_id)
            )).scalar_one_or_none()
            if loader is None:
                raise HTTPException(status_code=404, detail="loader not found")
            if loader.revoked:
                raise HTTPException(status_code=410, detail="loader revoked")
            if loader.owner_account_id != account.id:
                raise HTTPException(status_code=403, detail="loader not owned by account")
            k_master = app.state.kms.get_master(loader.id)
            iters = 100000
            sealed, blob_salt, _blob_key = compiler.seal_remote(
                body.source, k_master, flags=body.flags,
                symbols=body.symbols, iters=iters,
            )
            blob_sha = compiler.sha256_hex(sealed)
            blob_id = _rid("blb")
            row = Blob(
                id=blob_id,
                loader_id=loader.id,
                owner_account_id=account.id,
                sealed_body=sealed,
                blob_sha256=blob_sha,
                blob_salt=blob_salt,
                kdf_iters=iters,
            )
            sess.add(row)
            await sess.commit()
            return CompileResponse(
                blob_id=blob_id,
                blob_sha256=blob_sha,
                sealed_blob=base64.b64encode(sealed).decode("ascii"),
                created_at=_ms(row.created_at or _utcnow()),
            )

    @app.get("/v1/blob/{blob_id}")
    async def get_blob(blob_id: str, request: Request):
        """Return the raw sealed body for a blob by id.

        Public (no bearer): the sealed body is useless without a per-session
        envelope. Per-IP sliding-window rate limit guards against mass pulls.
        """
        if request.client is not None:
            ip = request.client.host or "unknown"
        else:
            ip = "unknown"
        rl = rate_limiter()
        if not rl.allow(f"ip:{ip}:blob", cfg.rate_blob_fetch_per_hour, 3600.0):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="blob fetch rate limit exceeded",
            )
        sm = get_sessionmaker()
        async with sm() as sess:
            blob = (await sess.execute(
                select(Blob).where(Blob.id == blob_id)
            )).scalar_one_or_none()
            if blob is None:
                raise HTTPException(status_code=404, detail="blob not found")
            if blob.revoked:
                raise HTTPException(status_code=410, detail="blob revoked")
            body_bytes = bytes(blob.sealed_body)
        return Response(content=body_bytes, media_type="application/octet-stream")

    @app.get("/v1/integrity/{blob_id}", response_model=IntegrityResponse)
    async def integrity_endpoint(
        blob_id: str,
        account: Account = Depends(require_account),
    ):
        sm = get_sessionmaker()
        async with sm() as sess:
            blob = (await sess.execute(select(Blob).where(Blob.id == blob_id))).scalar_one_or_none()
            if blob is None:
                raise HTTPException(status_code=404, detail="blob not found")
            if blob.revoked:
                raise HTTPException(status_code=410, detail="blob revoked")
            if blob.owner_account_id != account.id:
                raise HTTPException(status_code=403, detail="blob not owned by account")
            k_master = app.state.kms.get_master(blob.loader_id)
            blob_salt_bytes = bytes(blob.blob_salt or b"")
            iters = int(blob.kdf_iters or 100000)
        if not blob_salt_bytes:
            raise HTTPException(status_code=409, detail="blob missing salt")
        try:
            blob_key = compiler.blob_key_from_master(k_master, blob_salt_bytes, iters)
            _ = compiler.unseal_with_blob_key(blob.sealed_body, blob_key)
        except Exception:
            raise HTTPException(status_code=409, detail="integrity check failed")
        current_sha = compiler.sha256_hex(blob.sealed_body)
        if current_sha != blob.blob_sha256:
            raise HTTPException(status_code=409, detail="sha drift")
        return IntegrityResponse(ok=True, blob_sha256=current_sha, verified_at=_ms(_utcnow()))

    @app.post("/v1/session/challenge", response_model=ChallengeResponse)
    async def session_challenge(body: ChallengeRequest):
        try:
            nonce_c = bytes.fromhex(body.nonce_c)
        except ValueError:
            raise HTTPException(status_code=400, detail="nonce_c not hex")
        if len(nonce_c) != 16:
            raise HTTPException(status_code=400, detail="nonce_c must be 16 bytes")
        sm = get_sessionmaker()
        async with sm() as sess:
            blob = (await sess.execute(select(Blob).where(Blob.id == body.blob_id))).scalar_one_or_none()
            if blob is None:
                raise HTTPException(status_code=404, detail="blob not found")
            if blob.revoked:
                raise HTTPException(status_code=410, detail="blob revoked")
            if blob.loader_id != body.loader_id:
                raise HTTPException(status_code=400, detail="loader_id mismatch")
            loader = (await sess.execute(select(Loader).where(Loader.id == body.loader_id))).scalar_one_or_none()
            if loader is None:
                raise HTTPException(status_code=404, detail="loader not found")
            if loader.revoked:
                raise HTTPException(status_code=410, detail="loader revoked")
            nonce_s = secrets.token_bytes(16)
            challenge_id = _rid("chg")
            deadline = _utcnow() + dt.timedelta(milliseconds=cfg.session_ttl_ms)
            sess.add(Challenge(
                id=challenge_id,
                blob_id=body.blob_id,
                loader_id=body.loader_id,
                device_fp=body.device_fp,
                nonce_c=nonce_c,
                nonce_s=nonce_s,
                deadline=deadline,
                consumed=False,
            ))
            await sess.commit()
        return ChallengeResponse(
            challenge_id=challenge_id,
            nonce_s=nonce_s.hex(),
            ttl_ms=cfg.session_ttl_ms,
        )

    @app.post("/v1/session/complete", response_model=CompleteResponse)
    async def session_complete(body: CompleteRequest):
        try:
            proof = bytes.fromhex(body.proof)
        except ValueError:
            raise HTTPException(status_code=400, detail="proof not hex")
        sm = get_sessionmaker()
        async with sm() as sess:
            chal = (await sess.execute(
                select(Challenge).where(Challenge.id == body.challenge_id)
            )).scalar_one_or_none()
            if chal is None:
                raise HTTPException(status_code=404, detail="challenge not found")
            if chal.consumed:
                raise HTTPException(status_code=409, detail="challenge consumed")
            now = _utcnow()
            deadline = chal.deadline
            if deadline.tzinfo is None:
                deadline = deadline.replace(tzinfo=dt.timezone.utc)
            if deadline < now:
                raise HTTPException(status_code=408, detail="challenge expired")
            loader = (await sess.execute(select(Loader).where(Loader.id == chal.loader_id))).scalar_one_or_none()
            if loader is None or loader.revoked:
                raise HTTPException(status_code=410, detail="loader unavailable")
            blob = (await sess.execute(select(Blob).where(Blob.id == chal.blob_id))).scalar_one_or_none()
            if blob is None or blob.revoked:
                raise HTTPException(status_code=410, detail="blob unavailable")

            k_hmac = app.state.kms.get_hmac(chal.loader_id)
            k_master = app.state.kms.get_master(chal.loader_id)
            k_sign_priv = app.state.kms.get_sign_priv(chal.loader_id)
            blob_salt_bytes = bytes(blob.blob_salt or b"")
            if not blob_salt_bytes:
                raise HTTPException(status_code=409, detail="blob missing salt")
            blob_key = compiler.blob_key_from_master(
                k_master, blob_salt_bytes, int(blob.kdf_iters or 100000)
            )

            attest_msg = (
                b"svm-attest|v1|"
                + chal.blob_id.encode("ascii")
                + chal.loader_id.encode("ascii")
                + chal.device_fp.encode("ascii")
                + bytes(chal.nonce_c)
                + bytes(chal.nonce_s)
            )
            expected = hmac.new(k_hmac, attest_msg, "sha256").digest()
            if not hmac.compare_digest(expected, proof):
                chal.consumed = True
                await sess.commit()
                raise HTTPException(status_code=403, detail="proof mismatch")

            chal.consumed = True

            session_id = _rid("ses")
            k_session = blake2s(
                k_master + chal.id.encode("ascii") + chal.device_fp.encode("ascii"),
                key=b"",
                out_len=32,
            )
            body_len = len(blob.sealed_body) - compiler.HEADER_LEN - compiler.MAC_LEN
            import struct as _st
            blob_nonce = blake2s(compiler.MAGIC + _st.pack("<I", body_len), key=b"", out_len=24)

            expires_at = _utcnow() + dt.timedelta(milliseconds=cfg.session_ttl_ms)
            envelope_body = json.dumps({
                "session_id": session_id,
                "key": blob_key.hex(),
                "key_session": k_session.hex(),
                "nonce": blob_nonce.hex(),
                "expires": _ms(expires_at),
            }).encode("utf-8")

            ephemeral = blake2s(
                k_hmac + bytes(chal.nonce_c) + bytes(chal.nonce_s),
                key=b"",
                out_len=32,
            )
            env_nonce = secrets.token_bytes(24)
            env_ct = xchacha20(ephemeral, env_nonce, 0, envelope_body)
            env_kauth = blake2s(ephemeral + b"auth", key=b"", out_len=32)
            env_tag = poly1305(env_kauth, env_nonce + env_ct)
            sealed_envelope = env_nonce + env_ct + env_tag

            try:
                priv = load_pem_private_key(k_sign_priv, password=None)
            except Exception:
                priv = Ed25519PrivateKey.from_private_bytes(k_sign_priv)
            sig = priv.sign(sealed_envelope)

            sess.add(SessionRow(
                id=session_id,
                blob_id=chal.blob_id,
                loader_id=chal.loader_id,
                device_fp=chal.device_fp,
                expires_at=expires_at,
            ))
            await sess.commit()

        return CompleteResponse(
            session_id=session_id,
            envelope_sealed=base64.b64encode(sealed_envelope).decode("ascii"),
            envelope_sig=sig.hex(),
            expires=_ms(expires_at),
        )

    return app
