from __future__ import annotations

import hashlib
import struct

from shadowc.crypto import blake2s, fnv1a32, pbkdf2_hmac_sha256, poly1305, xchacha20

MAGIC = b"SVM1"
VERSION = 1
HEADER_LEN = 32
MAC_LEN = 16


def _flags_bits(flags: dict | None) -> int:
    if not flags:
        return 0
    b = 0
    if flags.get("anti_debug"):
        b |= 0x1
    if flags.get("strip_names"):
        b |= 0x2
    return b


def _emit_body(source: str, symbols: list[str] | None) -> tuple[bytes, int, int, int, int]:
    """Produce a canonical cleartext body with entry table, code, data and mask table."""
    syms = symbols or ["main"]
    entry_count = len(syms)
    entry_bytes = bytearray()
    entry_bytes += struct.pack("<I", entry_count)
    for i, name in enumerate(syms):
        name_hash = fnv1a32(name.lower().encode("utf-8"))
        entry_bytes += struct.pack("<II", name_hash, i * 8)
    code = bytearray()
    for i in range(len(syms)):
        code += struct.pack("<I", 0x1B000000)
        code += struct.pack("<I", 0x00000000)
    source_bytes = source.encode("utf-8")
    source_pad = (4 - (len(source_bytes) % 4)) % 4
    data = bytearray(source_bytes + b"\x00" * source_pad)
    mask = bytearray()
    for i in range(256):
        mask += blake2s(struct.pack("<I", i), key=b"", out_len=4)
    body = bytearray()
    entry_off = 0
    body += entry_bytes
    code_off = len(body)
    body += code
    data_off = len(body)
    body += data
    mask_off = len(body)
    body += mask
    return bytes(body), entry_off, code_off, data_off, mask_off


def seal_remote(source: str, k_master: bytes, flags: dict | None = None,
                symbols: list[str] | None = None, iters: int = 100000) -> bytes:
    """Seal source into header||ciphertext||mac using K_master as the XChaCha20 key.

    The server treats K_master as the authoritative blob key: the body is
    encrypted with it directly and the Poly1305 auth key is derived via BLAKE2s.
    iters is retained for future PBKDF2-based variants but is accepted here so
    callers that follow the compile protocol see no interface drift.
    """
    body, entry_off, code_off, data_off, mask_off = _emit_body(source, symbols)
    body_len = len(body)
    flag_bits = _flags_bits(flags)
    header = struct.pack(
        "<4sHHIIIIII",
        MAGIC,
        VERSION,
        flag_bits,
        body_len,
        entry_off,
        code_off,
        data_off,
        mask_off,
        iters,
    )
    assert len(header) == HEADER_LEN
    nonce = blake2s(MAGIC + struct.pack("<I", body_len), key=b"", out_len=24)
    ciphertext = xchacha20(k_master, nonce, 0, body)
    kauth = blake2s(k_master + b"auth", key=b"", out_len=32)
    tag = poly1305(kauth, header + ciphertext)
    return header + ciphertext + tag


def unseal_remote(blob: bytes, k_master: bytes) -> bytes:
    """Verify the Poly1305 MAC and decrypt the body with K_master."""
    if len(blob) < HEADER_LEN + MAC_LEN:
        raise ValueError("sealed blob too short")
    header = blob[:HEADER_LEN]
    tag = blob[-MAC_LEN:]
    ciphertext = blob[HEADER_LEN:-MAC_LEN]
    magic = header[:4]
    if magic != MAGIC:
        raise ValueError("bad magic")
    body_len = struct.unpack_from("<I", header, 8)[0]
    if body_len != len(ciphertext):
        raise ValueError("body length mismatch")
    kauth = blake2s(k_master + b"auth", key=b"", out_len=32)
    expected = poly1305(kauth, header + ciphertext)
    if not _ct_eq(expected, tag):
        raise ValueError("mac mismatch")
    nonce = blake2s(MAGIC + struct.pack("<I", body_len), key=b"", out_len=24)
    return xchacha20(k_master, nonce, 0, ciphertext)


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
