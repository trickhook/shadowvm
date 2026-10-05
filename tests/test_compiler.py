from __future__ import annotations

import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, "compiler"))

from shadowc import pack
from shadowc.codegen import OPCODES, _decode_opword
from shadowc.lexer import tokenize
from shadowc.parser import Parser
from shadowc.lower import lower


EXAMPLE_PATH = os.path.join(REPO, "examples", "hello.sdl")


def _load_example() -> str:
    with open(EXAMPLE_PATH, "r", encoding="utf-8") as f:
        return f.read()


def test_lex_hello_tokens() -> None:
    src = _load_example()
    toks = tokenize(src)
    assert toks[0].value == "fn"
    assert any(t.value == "main" for t in toks)
    assert any(t.value == "syscall" for t in toks)
    assert toks[-1].kind == "EOF"


def test_parse_hello_ast() -> None:
    src = _load_example()
    prog = Parser(tokenize(src)).parse_program()
    assert len(prog.funcs) == 1
    assert prog.funcs[0].name == "main"
    irp = lower(prog)
    assert len(irp.funcs) == 1
    assert irp.funcs[0].nvregs > 0


def test_blob_header_fields() -> None:
    src = _load_example()
    blob = pack.seal_local(src, "testpass", kdf_iters=100000, seed=1234)
    assert blob[0:4] == b"SVM1"
    version = struct.unpack_from("<H", blob, 4)[0]
    assert version == 0x0001
    hdr = pack.parse_header(blob)
    assert hdr.kdf_iters == 100000
    assert hdr.entry_off >= 16
    assert hdr.code_off > hdr.entry_off
    assert hdr.mask_off >= hdr.data_off
    assert hdr.body_len == hdr.mask_off + 1024


def test_round_trip_first_movi_is_seven() -> None:
    src = """fn main() {\n    let x = 7;\n    return x;\n}\n"""
    blob = pack.seal_local(src, "hunter2", kdf_iters=100000, seed=99)
    opened = pack.open_local(blob, "hunter2")
    code = pack.decode_code(opened.code_bytes, opened.mask_table, opened.kmaster, code_base=0)
    first = code[0]
    assert first["op"] == "movi", f"expected MOVI first, got {first['op']}"
    assert first["has_imm32"] is True
    assert first["imm32"] == 7, f"expected imm32=7, got {first['imm32']}"


def test_round_trip_hello_decodes() -> None:
    src = _load_example()
    blob = pack.seal_local(src, "p", kdf_iters=100000, seed=42)
    opened = pack.open_local(blob, "p")
    code = pack.decode_code(opened.code_bytes, opened.mask_table, opened.kmaster, code_base=0)
    ops_seen = {ins["op"] for ins in code}
    assert "movi" in ops_seen
    assert "mul" in ops_seen
    assert "syscall" in ops_seen
    assert "ret" in ops_seen


def test_wrong_password_rejects() -> None:
    src = _load_example()
    blob = pack.seal_local(src, "right", kdf_iters=100000, seed=1)
    try:
        pack.open_local(blob, "wrong")
    except ValueError:
        return
    raise AssertionError("open_local should have failed with wrong password")
