from __future__ import annotations

import random
import struct

import pytest

from shadowc.codegen import _assign_variants, _encode_opword, EmittedInstr, OPCODE_NAMES
from shadowc.crypto import pc_mask

SVM_REAL_OPS = 0x1C
SVM_VARIANT_LIMIT = 0x70


def _vm_decode(word: int, mask_v: bytes, kmaster: bytes, pc: int) -> tuple[int, int, int, int, int]:
    pm = int.from_bytes(pc_mask(kmaster, pc), "little")
    word ^= pm
    mv = int.from_bytes(mask_v, "little")
    word ^= mv
    variant = (word >> 24) & 0xFF
    assert variant < SVM_VARIANT_LIMIT, f"variant {variant:#x} >= SVM_VARIANT_LIMIT"
    real = variant & 0x1F
    assert real < SVM_REAL_OPS, f"real {real:#x} >= SVM_REAL_OPS"
    b2 = (word >> 16) & 0xFF
    b1 = (word >> 8) & 0xFF
    b0 = word & 0xFF
    dst = (b2 >> 3) & 0x1F
    src1 = ((b2 & 0x7) << 2) | ((b1 >> 6) & 0x3)
    src2 = (b1 >> 1) & 0x1F
    imm9 = ((b1 & 1) << 8) | b0
    return real, dst, src1, src2, imm9


@pytest.mark.parametrize("real_op", list(range(SVM_REAL_OPS)))
def test_every_variant_roundtrips(real_op: int) -> None:
    rng = random.Random(0xC0FFEE ^ real_op)
    instrs = [EmittedInstr(op=OPCODE_NAMES[real_op], opcode=real_op, dst=1, src1=2, src2=3, imm9=0x55, pc=0, has_imm32=False, imm32=0) for _ in range(1)]
    vmap, masks = _assign_variants(instrs, rng)
    assert vmap[real_op]
    for variant_id in vmap[real_op]:
        assert variant_id & 0x1F == real_op, f"variant {variant_id:#x} does not recover op {real_op:#x} via & 0x1F"
        assert variant_id < SVM_VARIANT_LIMIT
        word = _encode_opword(variant_id, 1, 2, 3, 0x55)
        word ^= int.from_bytes(masks[variant_id], "little")
        kmaster = b"\x11" * 32
        pm = int.from_bytes(pc_mask(kmaster, 0), "little")
        sealed = (word ^ pm) & 0xFFFFFFFF
        real, dst, src1, src2, imm9 = _vm_decode(sealed, masks[variant_id], kmaster, 0)
        assert real == real_op
        assert dst == 1
        assert src1 == 2
        assert src2 == 3
        assert imm9 == 0x55


def test_variant_limit_blocks_bad_bytes() -> None:
    for v in range(SVM_VARIANT_LIMIT, 256):
        assert v >= SVM_VARIANT_LIMIT


def test_masked_bits_zero_cannot_promote_opcode() -> None:
    for real in range(SVM_REAL_OPS):
        for v in range(3):
            vid = real + v * 0x20
            if vid >= SVM_VARIANT_LIMIT:
                continue
            assert vid & 0x1F == real
