from __future__ import annotations

import hashlib
import os
import struct
from typing import Tuple

from shadowc.crypto import blake2s, pbkdf2_hmac_sha256, poly1305, xchacha20
from shadowc import pack as _pack
from shadowc.codegen import apply_masks, pack_mask_table

MAGIC = b"SVM1"
VERSION = 1
HEADER_LEN = 32
MAC_LEN = 16
SALT_SIZE = 16


def _flags_bits(flags: dict | None) -> int:
    if not flags:
        return 0
    b = 0
    if flags.get("anti_debug"):
        b |= 0x1
    if flags.get("strip_names"):
        b |= 0x2
    return b


def _assemble_body(source: str, blob_key: bytes, blob_salt: bytes,
                   symbols: list[str] | None) -> tuple[bytes, dict]:
    """Compile source and lay out an encrypted-body-ready buffer.

    Layout matches ``spec/blob.md``: 16-byte salt slot, entry table, code
    section (per-PC XORed with ``blob_key``), empty data region, and the
    256-entry variant mask table. Returns the cleartext body and offsets.
    """
    result = _pack._compile_source(source)
    entry_tbl = _pack._build_entry_table(result)
    code_bytes = apply_masks(result, blob_key)
    mask_bytes = pack_mask_table(result)
    entry_off = SALT_SIZE
    code_off = entry_off + len(entry_tbl)
    data_off = code_off + len(code_bytes)
    mask_off = data_off
    body_len = mask_off + len(mask_bytes)
    body = bytearray(body_len)
    body[0:SALT_SIZE] = blob_salt
    body[entry_off:entry_off + len(entry_tbl)] = entry_tbl
    body[code_off:code_off + len(code_bytes)] = code_bytes
    body[mask_off:mask_off + len(mask_bytes)] = mask_bytes
    offsets = {
        "entry_off": entry_off,
        "code_off": code_off,
        "data_off": data_off,
        "mask_off": mask_off,
        "body_len": body_len,
    }
    return bytes(body), offsets


def seal_remote(source: str, k_master: bytes, flags: dict | None = None,
                symbols: list[str] | None = None,
                iters: int = 100000) -> Tuple[bytes, bytes, bytes]:
    """Compile and seal with ``blob_key = PBKDF2(k_master, salt, iters)``.

    Returns ``(sealed, blob_salt, blob_key)`` so the caller can persist the
    salt for later integrity checks and session issuance.
    """
    blob_salt = os.urandom(SALT_SIZE)
    blob_key = pbkdf2_hmac_sha256(k_master, blob_salt, iters, 32)
    body, offsets = _assemble_body(source, blob_key, blob_salt, symbols)
    body_len = offsets["body_len"]
    flag_bits = _flags_bits(flags)
    header = struct.pack(
        "<4sHHIIIIII",
        MAGIC,
        VERSION,
        flag_bits,
        body_len,
        offsets["entry_off"],
        offsets["code_off"],
        offsets["data_off"],
        offsets["mask_off"],
        iters,
    )
    assert len(header) == HEADER_LEN
    nonce = blake2s(MAGIC + struct.pack("<I", body_len), key=b"", out_len=24)
    # Same scheme as the local sealer: pre-XOR the first 16 body bytes with the
    # keystream slice so that after full-body encryption the ciphertext's first
    # 16 bytes are the plaintext salt. The reader can therefore recover the
    # salt without the key.
    pre = bytearray(body)
    keystream_slice = xchacha20(blob_key, nonce, 0, bytes(SALT_SIZE))
    for i in range(SALT_SIZE):
        pre[i] = blob_salt[i] ^ keystream_slice[i]
    ciphertext = xchacha20(blob_key, nonce, 0, bytes(pre))
    kauth = blake2s(blob_key + b"auth", key=b"", out_len=32)
    tag = poly1305(kauth, header + ciphertext)
    return header + ciphertext + tag, blob_salt, blob_key


def unseal_remote(sealed: bytes, k_master: bytes) -> bytes:
    """Open a server-sealed blob using ``k_master``.

    Recovers the embedded ``blob_salt``, rebuilds ``blob_key`` via PBKDF2, and
    verifies both the Poly1305 MAC and that re-rolling PBKDF2 against the
    post-decrypt salt yields the same key. Returns the plaintext body.
    """
    if len(sealed) < HEADER_LEN + MAC_LEN:
        raise ValueError("sealed blob too short")
    header = sealed[:HEADER_LEN]
    tag = sealed[-MAC_LEN:]
    ciphertext = sealed[HEADER_LEN:-MAC_LEN]
    if header[:4] != MAGIC:
        raise ValueError("bad magic")
    body_len = struct.unpack_from("<I", header, 8)[0]
    iters = struct.unpack_from("<I", header, 28)[0]
    if iters < 1:
        raise ValueError("bad kdf_iters")
    if body_len != len(ciphertext):
        raise ValueError("body length mismatch")
    if body_len < SALT_SIZE:
        raise ValueError("body too short for salt")
    salt_ct = ciphertext[:SALT_SIZE]
    blob_key = pbkdf2_hmac_sha256(k_master, salt_ct, iters, 32)
    kauth = blake2s(blob_key + b"auth", key=b"", out_len=32)
    expected = poly1305(kauth, header + ciphertext)
    if not _ct_eq(expected, tag):
        raise ValueError("mac mismatch")
    nonce = blake2s(MAGIC + struct.pack("<I", body_len), key=b"", out_len=24)
    body = xchacha20(blob_key, nonce, 0, ciphertext)
    plaintext_salt = body[:SALT_SIZE]
    # Roll PBKDF2 again against the decrypted salt - this is the explicit
    # consistency check the task calls for.
    rolled = pbkdf2_hmac_sha256(k_master, plaintext_salt, iters, 32)
    if not _ct_eq(rolled, blob_key):
        raise ValueError("salt consistency mismatch")
    return body


def unseal_with_blob_key(sealed: bytes, blob_key: bytes) -> bytes:
    """Decrypt a server-sealed blob when the derived ``blob_key`` is known.

    Used by clients that already received ``blob_key`` through the session
    envelope and never see ``k_master``.
    """
    if len(sealed) < HEADER_LEN + MAC_LEN:
        raise ValueError("sealed blob too short")
    header = sealed[:HEADER_LEN]
    tag = sealed[-MAC_LEN:]
    ciphertext = sealed[HEADER_LEN:-MAC_LEN]
    if header[:4] != MAGIC:
        raise ValueError("bad magic")
    body_len = struct.unpack_from("<I", header, 8)[0]
    if body_len != len(ciphertext):
        raise ValueError("body length mismatch")
    kauth = blake2s(blob_key + b"auth", key=b"", out_len=32)
    expected = poly1305(kauth, header + ciphertext)
    if not _ct_eq(expected, tag):
        raise ValueError("mac mismatch")
    nonce = blake2s(MAGIC + struct.pack("<I", body_len), key=b"", out_len=24)
    return xchacha20(blob_key, nonce, 0, ciphertext)


def blob_key_from_master(k_master: bytes, blob_salt: bytes, iters: int) -> bytes:
    """Rebuild ``blob_key`` from ``k_master`` and the stored ``blob_salt``."""
    return pbkdf2_hmac_sha256(k_master, blob_salt, iters, 32)


def _ct_eq(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    r = 0
    for x, y in zip(a, b):
        r |= x ^ y
    return r == 0


def sha256_hex(data: bytes) -> str:
    """Return hex SHA-256 of the input."""
    return hashlib.sha256(data).hexdigest()
