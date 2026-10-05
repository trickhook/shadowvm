from __future__ import annotations

__all__ = [
    "xchacha20",
    "poly1305",
    "pbkdf2_hmac_sha256",
    "blake2s",
    "fnv1a32",
    "pc_mask",
    "secure_zero",
]


def xchacha20(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    raise NotImplementedError


def poly1305(key: bytes, msg: bytes) -> bytes:
    raise NotImplementedError


def pbkdf2_hmac_sha256(password: bytes, salt: bytes, iters: int, out_len: int) -> bytes:
    raise NotImplementedError


def blake2s(data: bytes, key: bytes = b"", out_len: int = 32) -> bytes:
    raise NotImplementedError


def fnv1a32(data: bytes) -> int:
    raise NotImplementedError


def pc_mask(key: bytes, pc: int) -> bytes:
    raise NotImplementedError


def secure_zero(data: bytearray) -> None:
    raise NotImplementedError
