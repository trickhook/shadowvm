from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat, load_pem_private_key,
)


SEED_1 = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
PUB_1  = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")


def test_seed_derives_rfc_pubkey():
    priv = Ed25519PrivateKey.from_private_bytes(SEED_1)
    pub = priv.public_key().public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw,
    )
    assert pub == PUB_1


def test_signatures_are_deterministic():
    priv = Ed25519PrivateKey.from_private_bytes(SEED_1)
    msg = b"svm-envelope|v1|deterministic-sanity-check"
    sig_a = priv.sign(msg)
    sig_b = priv.sign(msg)
    assert sig_a == sig_b
    assert len(sig_a) == 64


def test_verify_rejects_bitflip():
    priv = Ed25519PrivateKey.from_private_bytes(SEED_1)
    pub = priv.public_key()
    msg = b"svm-session-complete"
    sig = bytearray(priv.sign(msg))
    pub.verify(bytes(sig), msg)
    sig[0] ^= 0x01
    with pytest.raises(InvalidSignature):
        pub.verify(bytes(sig), msg)


def test_verify_rejects_wrong_message():
    priv = Ed25519PrivateKey.from_private_bytes(SEED_1)
    pub = priv.public_key()
    sig = priv.sign(b"original")
    with pytest.raises(InvalidSignature):
        pub.verify(sig, b"tampered")


def test_server_envelope_signature_roundtrips():
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    pub_raw = priv.public_key().public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw,
    )
    reloaded = load_pem_private_key(priv_pem, password=None)
    envelope = b"svm-envelope|v1|session_payload"
    sig = reloaded.sign(envelope)
    verifier = Ed25519PublicKey.from_public_bytes(pub_raw)
    verifier.verify(sig, envelope)
    tampered = bytearray(sig)
    tampered[-1] ^= 0x80
    with pytest.raises(InvalidSignature):
        verifier.verify(bytes(tampered), envelope)
