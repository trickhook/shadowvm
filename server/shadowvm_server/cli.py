from __future__ import annotations

import argparse
import asyncio
import secrets
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from sqlalchemy import select

from .auth import hash_token
from .config import load as load_config
from .db import Account, Blob, Loader, create_all, get_sessionmaker, init_engine
from .kms import build_kms


def _rid(prefix: str, n: int = 8) -> str:
    return f"{prefix}_{secrets.token_hex(n)}"


async def _init(cfg):
    init_engine(cfg.db_url)
    await create_all()
    kms = build_kms(cfg.kms_backend, cfg.kms_keyring)
    return kms


def _print(line: str) -> None:
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


async def _cmd_init(cfg, _args):
    await _init(cfg)
    _print(f"db ready at {cfg.db_url}")
    _print(f"kms backend {cfg.kms_backend} path {cfg.kms_keyring}")


async def _cmd_account_add(cfg, args):
    await _init(cfg)
    token = secrets.token_urlsafe(32)
    acc = Account(
        id=_rid("acc"),
        name=args.name,
        api_token_hash=hash_token(token),
        disabled=False,
    )
    sm = get_sessionmaker()
    async with sm() as sess:
        sess.add(acc)
        await sess.commit()
    _print(f"account_id={acc.id}")
    _print(f"api_token={token}")


async def _cmd_account_revoke(cfg, args):
    await _init(cfg)
    sm = get_sessionmaker()
    async with sm() as sess:
        acc = (await sess.execute(select(Account).where(Account.id == args.id))).scalar_one_or_none()
        if acc is None:
            _print("not found"); return
        acc.disabled = True
        await sess.commit()
    _print(f"revoked {args.id}")


async def _cmd_loader_create(cfg, args):
    kms = await _init(cfg)
    k_master = secrets.token_bytes(32)
    k_hmac = secrets.token_bytes(32)
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pub_raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    loader_id = _rid("lid")
    kms.put_loader(loader_id, k_master, k_hmac, priv_pem, pub_raw)
    sm = get_sessionmaker()
    async with sm() as sess:
        acc = (await sess.execute(select(Account).where(Account.id == args.owner))).scalar_one_or_none()
        if acc is None:
            _print("owner not found"); return
        sess.add(Loader(
            id=loader_id,
            name=args.name,
            k_hmac=k_hmac,
            k_master=k_master,
            k_sign_privkey_wrapped=priv_pem,
            k_sign_pubkey=pub_raw,
            owner_account_id=args.owner,
        ))
        await sess.commit()
    _print(f"loader_id={loader_id}")


async def _cmd_loader_revoke(cfg, args):
    await _init(cfg)
    sm = get_sessionmaker()
    async with sm() as sess:
        row = (await sess.execute(select(Loader).where(Loader.id == args.id))).scalar_one_or_none()
        if row is None:
            _print("not found"); return
        row.revoked = True
        await sess.commit()
    _print(f"revoked {args.id}")


async def _cmd_blob_revoke(cfg, args):
    await _init(cfg)
    sm = get_sessionmaker()
    async with sm() as sess:
        row = (await sess.execute(select(Blob).where(Blob.id == args.id))).scalar_one_or_none()
        if row is None:
            _print("not found"); return
        row.revoked = True
        await sess.commit()
    _print(f"revoked {args.id}")


async def _cmd_loader_export_pub(cfg, args):
    await _init(cfg)
    sm = get_sessionmaker()
    async with sm() as sess:
        row = (await sess.execute(select(Loader).where(Loader.id == args.id))).scalar_one_or_none()
        if row is None:
            _print("not found"); return
        out = bytes(row.k_sign_pubkey) + bytes(row.k_hmac)
    Path(args.o).write_bytes(out)
    _print(f"wrote {args.o} ({len(out)} bytes)")


def run(argv: list[str]) -> None:
    """Entrypoint for the admin CLI."""
    parser = argparse.ArgumentParser(prog="shadowvm-server admin")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")

    account = sub.add_parser("account")
    acc_sub = account.add_subparsers(dest="acc_cmd", required=True)
    add = acc_sub.add_parser("add")
    add.add_argument("--name", required=True)
    rev = acc_sub.add_parser("revoke")
    rev.add_argument("--id", required=True)

    loader = sub.add_parser("loader")
    ld_sub = loader.add_subparsers(dest="ld_cmd", required=True)
    cr = ld_sub.add_parser("create")
    cr.add_argument("--name", required=True)
    cr.add_argument("--owner", required=True)
    lr = ld_sub.add_parser("revoke")
    lr.add_argument("--id", required=True)
    ep = ld_sub.add_parser("export-pub")
    ep.add_argument("--id", required=True)
    ep.add_argument("-o", required=True)

    blob = sub.add_parser("blob")
    bl_sub = blob.add_subparsers(dest="bl_cmd", required=True)
    br = bl_sub.add_parser("revoke")
    br.add_argument("--id", required=True)

    args = parser.parse_args(argv)
    cfg = load_config()
    if args.cmd == "init":
        asyncio.run(_cmd_init(cfg, args))
    elif args.cmd == "account" and args.acc_cmd == "add":
        asyncio.run(_cmd_account_add(cfg, args))
    elif args.cmd == "account" and args.acc_cmd == "revoke":
        asyncio.run(_cmd_account_revoke(cfg, args))
    elif args.cmd == "loader" and args.ld_cmd == "create":
        asyncio.run(_cmd_loader_create(cfg, args))
    elif args.cmd == "loader" and args.ld_cmd == "revoke":
        asyncio.run(_cmd_loader_revoke(cfg, args))
    elif args.cmd == "loader" and args.ld_cmd == "export-pub":
        asyncio.run(_cmd_loader_export_pub(cfg, args))
    elif args.cmd == "blob" and args.bl_cmd == "revoke":
        asyncio.run(_cmd_blob_revoke(cfg, args))
    else:
        parser.error("unknown command")
