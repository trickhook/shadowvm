from __future__ import annotations

import base64
import json
import logging
import os
import stat
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_LOG = logging.getLogger("shadowvm.kms")


class KMS:
    """Base KMS interface for per-loader key material."""
    def get_master(self, loader_id: str) -> bytes: raise NotImplementedError
    def get_hmac(self, loader_id: str) -> bytes: raise NotImplementedError
    def get_sign_priv(self, loader_id: str) -> bytes: raise NotImplementedError
    def get_sign_pub(self, loader_id: str) -> bytes: raise NotImplementedError
    def put_loader(self, loader_id: str, k_master: bytes, k_hmac: bytes,
                   k_sign_priv: bytes, k_sign_pub: bytes) -> None: raise NotImplementedError
    def has(self, loader_id: str) -> bool: raise NotImplementedError


class FileKMS(KMS):
    """JSON keyring stored on disk, 0600 permissions where supported."""
    def __init__(self, path: str):
        self.path = Path(path)
        if not self.path.exists():
            self._write({})

    def _read(self) -> dict:
        return json.loads(self.path.read_text(encoding="utf-8") or "{}")

    def _write(self, data: dict) -> None:
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        self._protect()

    def _protect(self) -> None:
        try:
            if sys.platform.startswith("win"):
                _LOG.info("keyring at %s on windows; relying on NTFS acls", self.path)
            else:
                os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError as exc:
            _LOG.warning("could not chmod keyring: %s", exc)

    def _entry(self, loader_id: str) -> dict:
        data = self._read()
        if loader_id not in data:
            raise KeyError(f"loader {loader_id} not in keyring")
        return data[loader_id]

    def get_master(self, loader_id: str) -> bytes:
        return base64.b64decode(self._entry(loader_id)["k_master"])

    def get_hmac(self, loader_id: str) -> bytes:
        return base64.b64decode(self._entry(loader_id)["k_hmac"])

    def get_sign_priv(self, loader_id: str) -> bytes:
        return base64.b64decode(self._entry(loader_id)["k_sign_privkey"])

    def get_sign_pub(self, loader_id: str) -> bytes:
        return base64.b64decode(self._entry(loader_id)["k_sign_pubkey"])

    def put_loader(self, loader_id: str, k_master: bytes, k_hmac: bytes,
                   k_sign_priv: bytes, k_sign_pub: bytes) -> None:
        data = self._read()
        data[loader_id] = {
            "k_master": base64.b64encode(k_master).decode("ascii"),
            "k_hmac": base64.b64encode(k_hmac).decode("ascii"),
            "k_sign_privkey": base64.b64encode(k_sign_priv).decode("ascii"),
            "k_sign_pubkey": base64.b64encode(k_sign_pub).decode("ascii"),
        }
        self._write(data)

    def has(self, loader_id: str) -> bool:
        return loader_id in self._read()


class EnvKMS(KMS):
    """Derives per-loader keys from a single SHADOWVM_MASTER_B64 via HKDF-SHA256."""
    def __init__(self):
        env = os.environ.get("SHADOWVM_MASTER_B64")
        if not env:
            raise RuntimeError("SHADOWVM_MASTER_B64 required for env KMS")
        self._root = base64.b64decode(env)
        self._cache: dict[str, dict] = {}

    def _derive(self, loader_id: str) -> dict:
        if loader_id in self._cache:
            return self._cache[loader_id]
        def h(info: str, n: int) -> bytes:
            return HKDF(algorithm=hashes.SHA256(), length=n, salt=None,
                        info=f"shadowvm|{loader_id}|{info}".encode()).derive(self._root)
        entry = {
            "k_master": h("master", 32),
            "k_hmac": h("hmac", 32),
            "k_sign_priv": h("sign", 32),
        }
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat, PrivateFormat, NoEncryption,
        )
        priv = Ed25519PrivateKey.from_private_bytes(entry["k_sign_priv"])
        entry["k_sign_priv_pem"] = priv.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )
        entry["k_sign_pub"] = priv.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        self._cache[loader_id] = entry
        return entry

    def get_master(self, loader_id: str) -> bytes:
        return self._derive(loader_id)["k_master"]

    def get_hmac(self, loader_id: str) -> bytes:
        return self._derive(loader_id)["k_hmac"]

    def get_sign_priv(self, loader_id: str) -> bytes:
        return self._derive(loader_id)["k_sign_priv"]

    def get_sign_pub(self, loader_id: str) -> bytes:
        return self._derive(loader_id)["k_sign_pub"]

    def put_loader(self, loader_id: str, k_master: bytes, k_hmac: bytes,
                   k_sign_priv: bytes, k_sign_pub: bytes) -> None:
        self._derive(loader_id)

    def has(self, loader_id: str) -> bool:
        return True


def build_kms(backend: str, keyring_path: str) -> KMS:
    """Return a KMS instance for the configured backend."""
    if backend == "file":
        return FileKMS(keyring_path)
    if backend == "env":
        return EnvKMS()
    raise ValueError(f"unknown kms backend {backend}")
