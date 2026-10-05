from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from . import pack


def _http(method: str, url: str, token: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    data = None
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            if not raw:
                return {}
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        raise SystemExit(f"HTTP {e.code} {e.reason}: {err_body}")
    except urllib.error.URLError as e:
        raise SystemExit(f"network error: {e.reason}")


def cmd_submit(args: argparse.Namespace) -> int:
    with open(args.source, "r", encoding="utf-8") as f:
        source = f.read()
    body = {
        "source": source,
        "target_loader_id": args.loader,
        "flags": {"anti_debug": bool(args.anti_debug), "strip_names": bool(args.strip_names)},
    }
    if args.symbols:
        body["symbols"] = [s.strip() for s in args.symbols.split(",") if s.strip()]
    resp = _http("POST", f"{args.server.rstrip('/')}/v1/compile", args.token, body)
    sealed_b64 = resp.get("sealed_blob")
    if not sealed_b64:
        raise SystemExit(f"server response missing sealed_blob: {resp}")
    sealed = base64.b64decode(sealed_b64)
    out_path = args.out or f"{os.path.splitext(args.source)[0]}.svm"
    with open(out_path, "wb") as f:
        f.write(sealed)
    sys.stdout.write(f"wrote {out_path} ({len(sealed)} bytes)\n")
    sys.stdout.write(f"blob_id={resp.get('blob_id')} sha256={resp.get('blob_sha256')}\n")
    return 0


def cmd_fetch(args: argparse.Namespace) -> int:
    resp = _http("GET", f"{args.server.rstrip('/')}/v1/blob/{args.blob_id}", args.token)
    sealed_b64 = resp.get("sealed_blob")
    if not sealed_b64:
        raise SystemExit(f"server response missing sealed_blob: {resp}")
    sealed = base64.b64decode(sealed_b64)
    with open(args.out, "wb") as f:
        f.write(sealed)
    sys.stdout.write(f"wrote {args.out} ({len(sealed)} bytes)\n")
    return 0


def cmd_integrity(args: argparse.Namespace) -> int:
    resp = _http("GET", f"{args.server.rstrip('/')}/v1/integrity/{args.blob_id}", args.token)
    sys.stdout.write(json.dumps(resp, indent=2) + "\n")
    return 0


def cmd_local(args: argparse.Namespace) -> int:
    sys.stderr.write(
        "warning: local-sealed blobs are DEV-ONLY and cannot be opened by svm_open_remote;\n"
        "         the server-sealed path is the only production flow.\n"
    )
    out_path = args.out or f"{os.path.splitext(args.source)[0]}.svm"
    kdf = max(args.kdf_iters, 100000)
    info = pack.write_local(args.source, args.password, out_path, kdf_iters=kdf)
    sys.stdout.write(
        f"wrote {out_path} ({len(info.raw)} bytes, code={info.code_size}B, "
        f"entries={info.entry_count}, kdf_iters={info.kdf_iters})\n"
    )
    return 0


def cmd_dump(args: argparse.Namespace) -> int:
    with open(args.blob, "rb") as f:
        data = f.read()
    opened = pack.open_local(data, args.password)
    sys.stdout.write(pack.disassemble(opened) + "\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="shadowc", description="ShadowVM DSL compiler and client")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("submit", help="submit source to server and save sealed blob")
    s.add_argument("source")
    s.add_argument("--server", required=True)
    s.add_argument("--token", required=True)
    s.add_argument("--loader", required=True)
    s.add_argument("--out")
    s.add_argument("--symbols", default="")
    s.add_argument("--anti-debug", action="store_true")
    s.add_argument("--strip-names", action="store_true")
    s.set_defaults(func=cmd_submit)

    s = sub.add_parser("fetch", help="fetch a previously sealed blob by id")
    s.add_argument("blob_id")
    s.add_argument("--server", required=True)
    s.add_argument("--token", required=True)
    s.add_argument("-o", "--out", required=True)
    s.set_defaults(func=cmd_fetch)

    s = sub.add_parser("integrity", help="query server-side integrity for a blob_id")
    s.add_argument("blob_id")
    s.add_argument("--server", required=True)
    s.add_argument("--token", required=True)
    s.set_defaults(func=cmd_integrity)

    s = sub.add_parser("local", help="DEV: compile + seal locally with a password")
    s.add_argument("source")
    s.add_argument("--password", required=True)
    s.add_argument("--out")
    s.add_argument("--kdf-iters", type=int, default=100000)
    s.set_defaults(func=cmd_local)

    s = sub.add_parser("dump", help="disassemble a local blob")
    s.add_argument("blob")
    s.add_argument("--password", required=True)
    s.set_defaults(func=cmd_dump)

    return p


def main(argv: Optional[list] = None) -> int:
    """Entry point for the shadowc CLI."""
    parser = build_parser()
    ns = parser.parse_args(argv)
    return ns.func(ns)


if __name__ == "__main__":
    raise SystemExit(main())
