from __future__ import annotations

import base64
import hmac
import json
import secrets
import struct
from pathlib import Path

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from httpx import ASGITransport, AsyncClient

from shadowc.crypto import blake2s, xchacha20, poly1305, fnv1a32
from shadowc import pack as spack
from shadowvm_server import compile as scompile
from shadowvm_server.api import create_app
from shadowvm_server.auth import rate_limiter
from shadowvm_server.db import create_all, dispose, get_sessionmaker, init_engine

from tests.test_server import _mk_config, _seed


pytestmark = pytest.mark.asyncio


HELLO_SDL = Path(__file__).resolve().parent.parent / "examples" / "jni-hello" / "src" / "hello.sdl"


@pytest_asyncio.fixture
async def seeded(tmp_path):
    cfg = _mk_config(tmp_path)
    init_engine(cfg.db_url)
    await create_all()
    info = await _seed(cfg)
    rate_limiter().reset()
    app = create_app(cfg, info["kms"])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield cfg, info, ac
    await dispose()


async def test_server_mediated_hello_end_to_end(seeded):
    cfg, info, ac = seeded
    hdrs = {"Authorization": f"Bearer {info['token']}"}

    source = HELLO_SDL.read_text(encoding="utf-8")

    r = await ac.post("/v1/compile", json={
        "source": source,
        "target_loader_id": info["loader_id"],
    }, headers=hdrs)
    assert r.status_code == 200, r.text
    jc = r.json()
    blob_id = jc["blob_id"]
    sealed_from_compile = base64.b64decode(jc["sealed_blob"])
    assert sealed_from_compile[:4] == b"SVM1"

    r = await ac.get(f"/v1/integrity/{blob_id}", headers=hdrs)
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True

    r = await ac.get(f"/v1/blob/{blob_id}")
    assert r.status_code == 200, r.text
    sealed = r.content
    assert sealed == sealed_from_compile

    device_fp = secrets.token_hex(16)
    nonce_c = secrets.token_bytes(16)
    r = await ac.post("/v1/session/challenge", json={
        "blob_id": blob_id,
        "loader_id": info["loader_id"],
        "device_fp": device_fp,
        "nonce_c": nonce_c.hex(),
    })
    assert r.status_code == 200, r.text
    jr = r.json()
    challenge_id = jr["challenge_id"]
    nonce_s = bytes.fromhex(jr["nonce_s"])

    attest = (
        b"svm-attest|v1|" + blob_id.encode("ascii")
        + info["loader_id"].encode("ascii") + device_fp.encode("ascii")
        + nonce_c + nonce_s
    )
    proof = hmac.new(info["k_hmac"], attest, "sha256").digest()
    r = await ac.post("/v1/session/complete", json={
        "challenge_id": challenge_id,
        "proof": proof.hex(),
    })
    assert r.status_code == 200, r.text
    jr = r.json()

    env_sealed = base64.b64decode(jr["envelope_sealed"])
    env_sig = bytes.fromhex(jr["envelope_sig"])
    pub = Ed25519PublicKey.from_public_bytes(info["k_sign_pub"])
    pub.verify(env_sig, env_sealed)

    env_nonce = env_sealed[:24]
    env_ct = env_sealed[24:-16]
    env_tag = env_sealed[-16:]
    ephemeral = blake2s(info["k_hmac"] + nonce_c + nonce_s, key=b"", out_len=32)
    env_kauth = blake2s(ephemeral + b"auth", key=b"", out_len=32)
    assert hmac.compare_digest(env_tag, poly1305(env_kauth, env_nonce + env_ct))
    env_plain = xchacha20(ephemeral, env_nonce, 0, env_ct)
    env = json.loads(env_plain.decode("utf-8"))
    blob_key = bytes.fromhex(env["key"])

    body = scompile.unseal_with_blob_key(sealed, blob_key)
    assert len(body) >= 32

    header = sealed[:32]
    entry_off = struct.unpack_from("<I", header, 12)[0]
    code_off = struct.unpack_from("<I", header, 16)[0]
    count = struct.unpack_from("<I", body, entry_off)[0]
    entries = {}
    for i in range(count):
        base = entry_off + 4 + i * 8
        name_hash = struct.unpack_from("<I", body, base)[0]
        offset = struct.unpack_from("<I", body, base + 4)[0]
        entries[name_hash] = offset

    hello_hash = fnv1a32(b"hello")
    assert hello_hash in entries, f"hello entry missing: have {list(entries)}"
    assert entries[hello_hash] >= 0

    assert body[code_off:code_off + 1] != b""
