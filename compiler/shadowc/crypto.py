from __future__ import annotations

import hashlib
import struct

__all__ = [
    "xchacha20",
    "poly1305",
    "pbkdf2_hmac_sha256",
    "blake2s",
    "fnv1a32",
    "pc_mask",
    "secure_zero",
]


_SIGMA = b"expand 32-byte k"


def _rotl32(x: int, n: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _qr(s: list, a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl32(s[b] ^ s[c], 7)


def _chacha20_block(key: bytes, counter: int, nonce12: bytes) -> bytes:
    state = list(struct.unpack("<4I", _SIGMA))
    state += list(struct.unpack("<8I", key))
    state.append(counter & 0xFFFFFFFF)
    state += list(struct.unpack("<3I", nonce12))
    working = state[:]
    for _ in range(10):
        _qr(working, 0, 4, 8, 12)
        _qr(working, 1, 5, 9, 13)
        _qr(working, 2, 6, 10, 14)
        _qr(working, 3, 7, 11, 15)
        _qr(working, 0, 5, 10, 15)
        _qr(working, 1, 6, 11, 12)
        _qr(working, 2, 7, 8, 13)
        _qr(working, 3, 4, 9, 14)
    out = bytearray(64)
    for i in range(16):
        v = (working[i] + state[i]) & 0xFFFFFFFF
        struct.pack_into("<I", out, i * 4, v)
    return bytes(out)


def _hchacha20(key: bytes, nonce16: bytes) -> bytes:
    state = list(struct.unpack("<4I", _SIGMA))
    state += list(struct.unpack("<8I", key))
    state += list(struct.unpack("<4I", nonce16))
    for _ in range(10):
        _qr(state, 0, 4, 8, 12)
        _qr(state, 1, 5, 9, 13)
        _qr(state, 2, 6, 10, 14)
        _qr(state, 3, 7, 11, 15)
        _qr(state, 0, 5, 10, 15)
        _qr(state, 1, 6, 11, 12)
        _qr(state, 2, 7, 8, 13)
        _qr(state, 3, 4, 9, 14)
    out = bytearray(32)
    for i, idx in enumerate((0, 1, 2, 3, 12, 13, 14, 15)):
        struct.pack_into("<I", out, i * 4, state[idx])
    return bytes(out)


def xchacha20(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if len(nonce) != 24:
        raise ValueError("nonce must be 24 bytes")
    subkey = _hchacha20(key, nonce[:16])
    nonce12 = b"\x00\x00\x00\x00" + nonce[16:24]
    out = bytearray(len(data))
    offset = 0
    blk_counter = counter & 0xFFFFFFFF
    while offset < len(data):
        ks = _chacha20_block(subkey, blk_counter, nonce12)
        chunk = data[offset:offset + 64]
        for i, b in enumerate(chunk):
            out[offset + i] = b ^ ks[i]
        offset += 64
        blk_counter = (blk_counter + 1) & 0xFFFFFFFF
    return bytes(out)


_P1305 = (1 << 130) - 5


def poly1305(key: bytes, msg: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    r = int.from_bytes(key[:16], "little")
    r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:32], "little")
    a = 0
    offset = 0
    n = len(msg)
    while offset < n:
        chunk = msg[offset:offset + 16]
        clen = len(chunk)
        block = int.from_bytes(chunk, "little") + (1 << (8 * clen))
        a = ((a + block) * r) % _P1305
        offset += 16
    a = (a + s) & ((1 << 128) - 1)
    return a.to_bytes(16, "little")


def pbkdf2_hmac_sha256(password: bytes, salt: bytes, iters: int, out_len: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, iters, out_len)


def blake2s(data: bytes, key: bytes = b"", out_len: int = 32) -> bytes:
    h = hashlib.blake2s(digest_size=out_len, key=key)
    h.update(data)
    return h.digest()


_FNV_OFFSET = 0x811C9DC5
_FNV_PRIME = 0x01000193


def fnv1a32(data: bytes) -> int:
    h = _FNV_OFFSET
    for b in data:
        h ^= b
        h = (h * _FNV_PRIME) & 0xFFFFFFFF
    return h


def pc_mask(key: bytes, pc: int) -> bytes:
    k = bytes(key[:32])
    return blake2s(struct.pack("<I", pc & 0xFFFFFFFF), key=k, out_len=4)


def secure_zero(data: bytearray) -> None:
    for i in range(len(data)):
        data[i] = 0
