from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "compiler"))

from shadowc.crypto import (
    blake2s,
    fnv1a32,
    pc_mask,
    pbkdf2_hmac_sha256,
    poly1305,
    secure_zero,
    xchacha20,
)


XCHACHA20_KEY = bytes(range(0x80, 0xa0))
XCHACHA20_NONCE = bytes.fromhex("404142434445464748494a4b4c4d4e4f5051525354555658")
XCHACHA20_PT = (
    b'The dhole (pronounced "dole") is also known as the Asiatic wild dog, '
    b'red dog, and whistling dog. It is about the size of a German shepherd '
    b'but looks more like a long-legged fox. This highly elusive and skilled '
    b'jumper is classified with wolves, coyotes, jackals, and foxes in the '
    b'taxonomic family Canidae.'
)
XCHACHA20_CT_FIRST16 = bytes.fromhex("7d0a2e6b7f7c65a236542630294e063b")


def test_xchacha20_vector():
    ct = xchacha20(XCHACHA20_KEY, XCHACHA20_NONCE, 1, XCHACHA20_PT)
    assert ct[:16] == XCHACHA20_CT_FIRST16
    pt = xchacha20(XCHACHA20_KEY, XCHACHA20_NONCE, 1, ct)
    assert pt == XCHACHA20_PT


def test_xchacha20_random_roundtrip():
    key = os.urandom(32)
    nonce = os.urandom(24)
    pt = os.urandom(4096)
    ct = xchacha20(key, nonce, 1, pt)
    assert len(ct) == len(pt)
    assert ct != pt
    rt = xchacha20(key, nonce, 1, ct)
    assert rt == pt


def test_poly1305_vector():
    key = bytes.fromhex(
        "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"
    )
    msg = b"Cryptographic Forum Research Group"
    tag = poly1305(key, msg)
    assert tag.hex() == "a8061dc1305136c6c22b8baf0c0127a9"


def test_pbkdf2_vector():
    out = pbkdf2_hmac_sha256(b"password", b"salt", 4096, 32)
    assert out.hex() == (
        "c5e478d59288c841aa530db6845c4c8d"
        "962893a001ce4e11a4963873aa98134a"
    )


def test_blake2s_vector():
    out = blake2s(b"", key=b"", out_len=32)
    assert out.hex() == (
        "69217a3079908094e11121d042354a7c"
        "1f55b6482ca1a51e1b250dfd1ed0eef9"
    )


def test_fnv1a32_vector():
    assert fnv1a32(b"hello") == 0x4F9F2CAB


def test_pc_mask_matches_blake2s():
    key = bytes.fromhex(
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
    )
    pc = 0x12345678
    mask = pc_mask(key, pc)
    expect = blake2s(
        pc.to_bytes(4, "little"),
        key=key[:32],
        out_len=4,
    )
    assert mask == expect
    assert len(mask) == 4


def test_secure_zero():
    buf = bytearray(b"\x01\x02\x03\x04\x05")
    secure_zero(buf)
    assert buf == bytearray(5)
