from __future__ import annotations

import os
import random
import struct
from dataclasses import dataclass
from typing import List, Optional, Tuple

from . import crypto
from .codegen import (
    CodegenResult,
    EmittedInstr,
    OPCODE_NAMES,
    OPCODES,
    _decode_opword,
    _instr_size,
    apply_masks,
    generate,
    pack_mask_table,
)
from .ir import IRProgram
from .lexer import tokenize
from .lower import lower
from .parser import Parser


MAGIC = b"SVM1"
VERSION = 0x0001
HEADER_SIZE = 32
MAC_SIZE = 16
SALT_SIZE = 16
MASK_TABLE_SIZE = 1024
MIN_KDF_ITERS = 100000
NONCE_SIZE = 24


@dataclass
class SealedBlob:
    raw: bytes
    code_size: int
    entry_count: int
    kdf_iters: int


def _compile_source(source: str, seed: Optional[int] = None) -> CodegenResult:
    toks = tokenize(source)
    prog = Parser(toks).parse_program()
    irp = lower(prog)
    rng = random.Random(seed) if seed is not None else random.Random()
    return generate(irp, rng)


def _build_entry_table(result: CodegenResult) -> bytes:
    out = bytearray()
    out.extend(struct.pack("<I", len(result.funcs)))
    for f in result.funcs:
        out.extend(struct.pack("<II", f.name_hash & 0xFFFFFFFF, f.offset & 0xFFFFFFFF))
    return bytes(out)


def _derive_nonce(body_len: int) -> bytes:
    return crypto.blake2s(MAGIC + struct.pack("<I", body_len & 0xFFFFFFFF), out_len=NONCE_SIZE)


def _derive_kauth(kmaster: bytes) -> bytes:
    return crypto.blake2s(kmaster + b"auth", out_len=32)


def _assemble_body(result: CodegenResult, kmaster: bytes, salt: bytes,
                   data_section: bytes = b"") -> Tuple[bytes, dict]:
    entry_tbl = _build_entry_table(result)
    code_bytes = apply_masks(result, kmaster)
    mask_bytes = pack_mask_table(result)
    salt_slot = SALT_SIZE
    entry_off = salt_slot
    code_off = entry_off + len(entry_tbl)
    data_off = code_off + len(code_bytes)
    mask_off = data_off + len(data_section)
    body_len = mask_off + len(mask_bytes)
    body = bytearray(body_len)
    body[0:salt_slot] = salt
    body[entry_off:entry_off + len(entry_tbl)] = entry_tbl
    body[code_off:code_off + len(code_bytes)] = code_bytes
    body[data_off:data_off + len(data_section)] = data_section
    body[mask_off:mask_off + len(mask_bytes)] = mask_bytes
    offsets = {
        "entry_off": entry_off,
        "code_off": code_off,
        "data_off": data_off,
        "mask_off": mask_off,
        "body_len": body_len,
    }
    return bytes(body), offsets


def _build_header(flags: int, offsets: dict, kdf_iters: int) -> bytes:
    hdr = bytearray(HEADER_SIZE)
    hdr[0:4] = MAGIC
    struct.pack_into("<H", hdr, 4, VERSION)
    struct.pack_into("<H", hdr, 6, flags & 0xFFFF)
    struct.pack_into("<I", hdr, 8, offsets["body_len"] & 0xFFFFFFFF)
    struct.pack_into("<I", hdr, 12, offsets["entry_off"] & 0xFFFFFFFF)
    struct.pack_into("<I", hdr, 16, offsets["code_off"] & 0xFFFFFFFF)
    struct.pack_into("<I", hdr, 20, offsets["data_off"] & 0xFFFFFFFF)
    struct.pack_into("<I", hdr, 24, offsets["mask_off"] & 0xFFFFFFFF)
    struct.pack_into("<I", hdr, 28, kdf_iters & 0xFFFFFFFF)
    return bytes(hdr)


def _seal_bytes(body: bytes, kmaster: bytes, salt: bytes, kdf_iters: int, flags: int,
                offsets: dict) -> bytes:
    nonce = _derive_nonce(offsets["body_len"])
    pre = bytearray(body)
    keystream_slice = crypto.xchacha20(kmaster, nonce, 0, bytes(SALT_SIZE))
    for i in range(SALT_SIZE):
        pre[i] = salt[i] ^ keystream_slice[i]
    ciphertext = crypto.xchacha20(kmaster, nonce, 0, bytes(pre))
    header = _build_header(flags, offsets, kdf_iters)
    kauth = _derive_kauth(kmaster)
    mac = crypto.poly1305(kauth, header + ciphertext)
    return header + ciphertext + mac


def seal_local(body_source: str, password: str, kdf_iters: int = 100000,
               flags: int = 0, seed: Optional[int] = None) -> bytes:
    """Compile source and seal into a blob using a local password."""
    if kdf_iters < MIN_KDF_ITERS:
        raise ValueError(f"kdf_iters must be >= {MIN_KDF_ITERS}")
    result = _compile_source(body_source, seed=seed)
    salt = os.urandom(SALT_SIZE)
    kmaster = crypto.pbkdf2_hmac_sha256(password.encode("utf-8"), salt, kdf_iters, 32)
    body, offsets = _assemble_body(result, kmaster, salt)
    return _seal_bytes(body, kmaster, salt, kdf_iters, flags, offsets)


def write_local(source_path: str, password: str, out_path: str,
                kdf_iters: int = 100000, flags: int = 0,
                seed: Optional[int] = None) -> SealedBlob:
    """Compile a source file and write a sealed .svm blob to disk."""
    with open(source_path, "r", encoding="utf-8") as f:
        src = f.read()
    blob = seal_local(src, password, kdf_iters=kdf_iters, flags=flags, seed=seed)
    with open(out_path, "wb") as f:
        f.write(blob)
    result = _compile_source(src, seed=seed)
    return SealedBlob(raw=blob, code_size=result.code_size, entry_count=len(result.funcs),
                      kdf_iters=kdf_iters)


@dataclass
class ParsedHeader:
    magic: bytes
    version: int
    flags: int
    body_len: int
    entry_off: int
    code_off: int
    data_off: int
    mask_off: int
    kdf_iters: int


def parse_header(blob: bytes) -> ParsedHeader:
    """Parse the 32-byte cleartext blob header."""
    if len(blob) < HEADER_SIZE + MAC_SIZE:
        raise ValueError("blob too small")
    if blob[0:4] != MAGIC:
        raise ValueError("bad magic")
    version = struct.unpack_from("<H", blob, 4)[0]
    flags = struct.unpack_from("<H", blob, 6)[0]
    body_len = struct.unpack_from("<I", blob, 8)[0]
    entry_off = struct.unpack_from("<I", blob, 12)[0]
    code_off = struct.unpack_from("<I", blob, 16)[0]
    data_off = struct.unpack_from("<I", blob, 20)[0]
    mask_off = struct.unpack_from("<I", blob, 24)[0]
    kdf_iters = struct.unpack_from("<I", blob, 28)[0]
    return ParsedHeader(MAGIC, version, flags, body_len, entry_off, code_off,
                        data_off, mask_off, kdf_iters)


@dataclass
class OpenedBlob:
    header: ParsedHeader
    body: bytes
    salt: bytes
    kmaster: bytes
    entry_table: List[Tuple[int, int]]
    code_bytes: bytes
    data_bytes: bytes
    mask_table: List[bytes]


def open_local(blob: bytes, password: str) -> OpenedBlob:
    """Open a locally-sealed blob and recover the cleartext body."""
    hdr = parse_header(blob)
    if hdr.version != VERSION:
        raise ValueError(f"unsupported version {hdr.version}")
    body_end = HEADER_SIZE + hdr.body_len
    if len(blob) < body_end + MAC_SIZE:
        raise ValueError("truncated blob")
    ciphertext = blob[HEADER_SIZE:body_end]
    mac_in = blob[body_end:body_end + MAC_SIZE]
    salt = ciphertext[:SALT_SIZE]
    kmaster = crypto.pbkdf2_hmac_sha256(password.encode("utf-8"), salt, hdr.kdf_iters, 32)
    kauth = _derive_kauth(kmaster)
    expected_mac = crypto.poly1305(kauth, blob[:HEADER_SIZE] + ciphertext)
    if not _ct_eq(expected_mac, mac_in):
        raise ValueError("MAC verification failed")
    nonce = _derive_nonce(hdr.body_len)
    body = crypto.xchacha20(kmaster, nonce, 0, ciphertext)
    entry_tbl_bytes = body[hdr.entry_off:hdr.code_off]
    count = struct.unpack_from("<I", entry_tbl_bytes, 0)[0]
    entry: List[Tuple[int, int]] = []
    for i in range(count):
        o = 4 + i * 8
        nh, off = struct.unpack_from("<II", entry_tbl_bytes, o)
        entry.append((nh, off))
    code_bytes = body[hdr.code_off:hdr.data_off]
    data_bytes = body[hdr.data_off:hdr.mask_off]
    mask_bytes = body[hdr.mask_off:hdr.mask_off + MASK_TABLE_SIZE]
    mask_table = [mask_bytes[i * 4:(i + 1) * 4] for i in range(256)]
    return OpenedBlob(header=hdr, body=body, salt=salt, kmaster=kmaster,
                      entry_table=entry, code_bytes=code_bytes, data_bytes=data_bytes,
                      mask_table=mask_table)


def _ct_eq(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0


def decode_code(code_bytes: bytes, mask_table: List[bytes], kmaster: bytes,
                code_base: int = 0) -> List[dict]:
    """Decode a block of code bytes back into a list of plain instruction dicts."""
    out: List[dict] = []
    i = 0
    n = len(code_bytes)
    while i + 4 <= n:
        word_bytes = code_bytes[i:i + 4]
        word = int.from_bytes(word_bytes, "little")
        pm = int.from_bytes(crypto.pc_mask(kmaster, code_base + i), "little")
        word ^= pm
        opcode = (word >> 24) & 0xFF
        mask_v = int.from_bytes(mask_table[opcode], "little")
        word ^= mask_v
        op_val, dst, src1, src2, imm9 = _decode_opword(word)
        name = _resolve_opname(op_val, mask_table)
        has_imm32 = name in ("movi", "jmp", "jeq", "jne", "jlt", "jgt")
        imm32 = 0
        size = 4
        if has_imm32 and i + 8 <= n:
            raw2 = int.from_bytes(code_bytes[i + 4:i + 8], "little")
            pm2 = int.from_bytes(crypto.pc_mask(kmaster, code_base + i + 4), "little")
            imm32 = (raw2 ^ pm2) & 0xFFFFFFFF
            size = 8
        out.append({
            "pc": code_base + i,
            "op": name,
            "opcode": op_val,
            "dst": dst,
            "src1": src1,
            "src2": src2,
            "imm9": imm9,
            "imm32": imm32,
            "has_imm32": has_imm32,
        })
        i += size
    return out


def _resolve_opname(variant_id: int, mask_table: List[bytes]) -> str:
    base = variant_id & 0x1F
    if base in OPCODE_NAMES and base <= 0x1B:
        return OPCODE_NAMES[base]
    if variant_id in OPCODE_NAMES:
        return OPCODE_NAMES[variant_id]
    return f"var_{variant_id:02x}"


def disassemble(opened: OpenedBlob) -> str:
    """Format an opened blob's code section as a disassembly string."""
    lines: List[str] = []
    lines.append(
        f"; header: version={opened.header.version:04x} flags={opened.header.flags:04x} "
        f"body_len={opened.header.body_len} kdf_iters={opened.header.kdf_iters}"
    )
    lines.append(f"; entry_table ({len(opened.entry_table)} entries)")
    for i, (nh, off) in enumerate(opened.entry_table):
        lines.append(f";   [{i}] name_hash=0x{nh:08x} offset=0x{off:08x}")
    code = decode_code(opened.code_bytes, opened.mask_table, opened.kmaster, code_base=0)
    for ins in code:
        if ins["has_imm32"]:
            lines.append(
                f"{ins['pc']:08x}  {ins['op']:<8} r{ins['dst']}, r{ins['src1']}, r{ins['src2']}, "
                f"imm32=0x{ins['imm32']:08x}"
            )
        else:
            lines.append(
                f"{ins['pc']:08x}  {ins['op']:<8} r{ins['dst']}, r{ins['src1']}, r{ins['src2']}, "
                f"imm9=0x{ins['imm9']:03x}"
            )
    return "\n".join(lines)
