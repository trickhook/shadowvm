from __future__ import annotations

import base64
import hmac
import json
import os
import secrets
import struct
import tempfile
from pathlib import Path

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from shadowc.crypto import blake2s, poly1305, xchacha20

from shadowvm_server.api import create_app
from shadowvm_server import compile as scompile
from shadowvm_server.auth import hash_token
from shadowvm_server.config import Config
from shadowvm_server.db import Account, Loader, get_sessionmaker, init_engine, create_all, drop_all, dispose
from shadowvm_server.kms import build_kms


pytestmark = pytest.mark.asyncio


def _mk_config(tmpdir: Path) -> Config:
    return Config(
        db_url=f"sqlite+aiosqlite:///{tmpdir / 'test.db'}",
        kms_backend="file",
        kms_keyring=str(tmpdir / "keyring.json"),
        listen="127.0.0.1:0",
        tls_cert=None,
        tls_key=None,
        rate_compile_per_hour=1000,
        rate_session_per_hour=1000,
        session_ttl_ms=60000,
    )


async def _seed(cfg: Config):
    kms = build_kms(cfg.kms_backend, cfg.kms_keyring)
    init_engine(cfg.db_url)
    await create_all()
    sm = get_sessionmaker()

    token = secrets.token_urlsafe(32)
    acc_id = "acc_" + secrets.token_hex(6)
    loader_id = "lid_" + secrets.token_hex(6)

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat, PublicFormat,
    )
    k_master = secrets.token_bytes(32)
    k_hmac = secrets.token_bytes(32)
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pub_raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    kms.put_loader(loader_id, k_master, k_hmac, priv_pem, pub_raw)

    async with sm() as sess:
        sess.add(Account(id=acc_id, name="t", api_token_hash=hash_token(token), disabled=False))
        sess.add(Loader(
            id=loader_id, name="lx",
            k_hmac=k_hmac, k_master=k_master,
            k_sign_privkey_wrapped=priv_pem, k_sign_pubkey=pub_raw,
            owner_account_id=acc_id,
        ))
        await sess.commit()

    return {
        "token": token, "acc_id": acc_id, "loader_id": loader_id,
        "k_master": k_master, "k_hmac": k_hmac, "k_sign_pub": pub_raw, "kms": kms,
    }


@pytest_asyncio.fixture
async def seeded():
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        cfg = _mk_config(tdp)
        info = await _seed(cfg)
        app = create_app(cfg, kms=info["kms"])
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            yield cfg, info, ac
        await drop_all()
        await dispose()


async def test_full_roundtrip(seeded):
    cfg, info, ac = seeded
    hdrs = {"Authorization": f"Bearer {info['token']}"}

    r = await ac.post("/v1/compile", json={
        "source": "func main() { nop }",
        "target_loader_id": info["loader_id"],
        "symbols": ["main"],
        "flags": {"anti_debug": True},
    }, headers=hdrs)
    assert r.status_code == 200, r.text
    jc = r.json()
    blob_id = jc["blob_id"]
    sealed = base64.b64decode(jc["sealed_blob"])
    assert sealed[:4] == b"SVM1"

    r = await ac.get(f"/v1/integrity/{blob_id}", headers=hdrs)
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True
    assert r.json()["blob_sha256"] == jc["blob_sha256"]

    nonce_c = secrets.token_bytes(16)
    device_fp = "deadbeef" * 8
    r = await ac.post("/v1/session/challenge", json={
        "blob_id": blob_id,
        "loader_id": info["loader_id"],
        "device_fp": device_fp,
        "nonce_c": nonce_c.hex(),
    })
    assert r.status_code == 200, r.text
    jch = r.json()
    nonce_s = bytes.fromhex(jch["nonce_s"])
    challenge_id = jch["challenge_id"]

    attest = (
        b"svm-attest|v1|"
        + blob_id.encode("ascii")
        + info["loader_id"].encode("ascii")
        + device_fp.encode("ascii")
        + nonce_c + nonce_s
    )
    proof = hmac.new(info["k_hmac"], attest, "sha256").digest()
    r = await ac.post("/v1/session/complete", json={
        "challenge_id": challenge_id,
        "proof": proof.hex(),
    })
    assert r.status_code == 200, r.text
    jr = r.json()

    sealed_env = base64.b64decode(jr["envelope_sealed"])
    sig = bytes.fromhex(jr["envelope_sig"])
    pub = Ed25519PublicKey.from_public_bytes(info["k_sign_pub"])
    pub.verify(sig, sealed_env)

    ephemeral = blake2s(info["k_hmac"] + nonce_c + nonce_s, key=b"", out_len=32)
    env_nonce = sealed_env[:24]
    env_tag = sealed_env[-16:]
    env_ct = sealed_env[24:-16]
    env_kauth = blake2s(ephemeral + b"auth", key=b"", out_len=32)
    expected_tag = poly1305(env_kauth, env_nonce + env_ct)
    assert hmac.compare_digest(env_tag, expected_tag)
    env_plain = xchacha20(ephemeral, env_nonce, 0, env_ct)
    env = json.loads(env_plain.decode("utf-8"))
    assert env["session_id"] == jr["session_id"]

    k_blob = bytes.fromhex(env["key"])
    k_session = bytes.fromhex(env["key_session"])
    expected_session = blake2s(
        info["k_master"] + challenge_id.encode("ascii") + device_fp.encode("ascii"),
        key=b"", out_len=32,
    )
    assert k_session == expected_session

    plain_body = scompile.unseal_remote(sealed, k_blob)
    assert sealed[:4] == b"SVM1"
    assert plain_body is not None and len(plain_body) > 0


async def test_integrity_tamper(seeded):
    cfg, info, ac = seeded
    hdrs = {"Authorization": f"Bearer {info['token']}"}
    r = await ac.post("/v1/compile", json={
        "source": "x",
        "target_loader_id": info["loader_id"],
    }, headers=hdrs)
    assert r.status_code == 200
    blob_id = r.json()["blob_id"]

    sm = get_sessionmaker()
    from shadowvm_server.db import Blob
    async with sm() as sess:
        b = (await sess.execute(select(Blob).where(Blob.id == blob_id))).scalar_one()
        corrupted = bytearray(b.sealed_body)
        corrupted[40] ^= 0xFF
        b.sealed_body = bytes(corrupted)
        await sess.commit()

    r = await ac.get(f"/v1/integrity/{blob_id}", headers=hdrs)
    assert r.status_code == 409


async def test_auth_rejects(seeded):
    cfg, info, ac = seeded
    r = await ac.post("/v1/compile", json={
        "source": "x", "target_loader_id": info["loader_id"],
    })
    assert r.status_code == 401
    r = await ac.post("/v1/compile", json={
        "source": "x", "target_loader_id": info["loader_id"],
    }, headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401
