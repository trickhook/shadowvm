from __future__ import annotations

import random
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .ir import Instr, IRFunc, IRProgram
from .regalloc import Allocation, allocate


OPCODES = {
    "halt":    0x00,
    "mov":     0x01,
    "movi":    0x02,
    "add":     0x03,
    "sub":     0x04,
    "mul":     0x05,
    "div":     0x06,
    "and":     0x07,
    "or":      0x08,
    "xor":     0x09,
    "shl":     0x0A,
    "shr":     0x0B,
    "not":     0x0C,
    "neg":     0x0D,
    "cmp":     0x0E,
    "jmp":     0x0F,
    "jeq":     0x10,
    "jne":     0x11,
    "jlt":     0x12,
    "jgt":     0x13,
    "load":    0x14,
    "store":   0x15,
    "push":    0x16,
    "pop":     0x17,
    "call":    0x18,
    "ret":     0x19,
    "syscall": 0x1A,
    "nop":     0x1B,
}

OPCODE_NAMES = {v: k for k, v in OPCODES.items()}

_BRANCH_OPS = {"jmp", "jeq", "jne", "jlt", "jgt"}

_SPILL_SCRATCH_A = 29
_SPILL_SCRATCH_B = 30


@dataclass
class EmittedInstr:
    op: str
    opcode: int
    dst: int
    src1: int
    src2: int
    imm9: int
    has_imm32: bool = False
    imm32: int = 0
    branch_label: Optional[str] = None
    call_target: Optional[str] = None
    pc: int = 0


@dataclass
class FuncOut:
    name: str
    name_hash: int
    offset: int
    instrs: List[EmittedInstr] = field(default_factory=list)


@dataclass
class CodegenResult:
    funcs: List[FuncOut] = field(default_factory=list)
    all_instrs: List[EmittedInstr] = field(default_factory=list)
    code_size: int = 0
    variant_map: Dict[int, List[int]] = field(default_factory=dict)
    variant_mask: List[bytes] = field(default_factory=list)
    func_index: Dict[str, int] = field(default_factory=dict)


def _encode_opword(opcode: int, dst: int, src1: int, src2: int, imm9: int) -> int:
    if not (0 <= opcode <= 0xFF):
        raise ValueError(f"opcode out of range: {opcode}")
    if not (0 <= dst <= 31):
        raise ValueError(f"dst out of range: {dst}")
    if not (0 <= src1 <= 31):
        raise ValueError(f"src1 out of range: {src1}")
    if not (0 <= src2 <= 31):
        raise ValueError(f"src2 out of range: {src2}")
    i9 = imm9 & 0x1FF
    return (opcode << 24) | (dst << 19) | (src1 << 14) | (src2 << 9) | i9


def _decode_opword(word: int) -> Tuple[int, int, int, int, int]:
    opcode = (word >> 24) & 0xFF
    dst = (word >> 19) & 0x1F
    src1 = (word >> 14) & 0x1F
    src2 = (word >> 9) & 0x1F
    imm9 = word & 0x1FF
    return opcode, dst, src1, src2, imm9


def _emit_opword(opcode: int, dst: int = 0, src1: int = 0, src2: int = 0, imm9: int = 0) -> EmittedInstr:
    return EmittedInstr(
        op=OPCODE_NAMES.get(opcode, "???"),
        opcode=opcode,
        dst=dst,
        src1=src1,
        src2=src2,
        imm9=imm9,
    )


class _FuncGen:
    def __init__(self, func: IRFunc, alloc: Allocation) -> None:
        self.func = func
        self.alloc = alloc
        self.out: List[EmittedInstr] = []
        self.labels: Dict[str, int] = {}

    def phys(self, vreg: int) -> Optional[int]:
        return self.alloc.reg_of.get(vreg)

    def is_spilled(self, vreg: int) -> bool:
        return vreg in self.alloc.spill_slot_of

    def load_src(self, vreg: int, scratch: int) -> int:
        if vreg < 0:
            return 0
        if self.is_spilled(vreg):
            slot = self.alloc.spill_slot_of[vreg]
            self.out.append(_emit_opword(OPCODES["load"], dst=scratch, src1=31, imm9=slot * 8))
            return scratch
        p = self.phys(vreg)
        if p is None:
            raise RuntimeError(f"vreg {vreg} has no allocation")
        return p

    def dst_setup(self, vreg: int) -> Tuple[int, Optional[int]]:
        if vreg < 0:
            return 0, None
        if self.is_spilled(vreg):
            return _SPILL_SCRATCH_B, self.alloc.spill_slot_of[vreg]
        p = self.phys(vreg)
        if p is None:
            raise RuntimeError(f"vreg {vreg} has no allocation")
        return p, None

    def write_dst(self, phys: int, slot: Optional[int]) -> None:
        if slot is None:
            return
        self.out.append(_emit_opword(OPCODES["store"], dst=31, src1=phys, imm9=slot * 8))

    def emit_prologue(self) -> None:
        n = self.alloc.nspills
        if n > 0:
            scratch = _SPILL_SCRATCH_A
            ins = _emit_opword(OPCODES["movi"], dst=scratch)
            ins.has_imm32 = True
            ins.imm32 = n * 8
            self.out.append(ins)
            self.out.append(_emit_opword(OPCODES["sub"], dst=31, src1=31, src2=scratch))
        for i, vreg in enumerate(self.func.params):
            if i >= 6:
                break
            arg_reg = i
            if self.is_spilled(vreg):
                slot = self.alloc.spill_slot_of[vreg]
                self.out.append(_emit_opword(OPCODES["store"], dst=31, src1=arg_reg, imm9=slot * 8))
            else:
                phys = self.phys(vreg)
                if phys is None or phys == arg_reg:
                    continue
                self.out.append(_emit_opword(OPCODES["mov"], dst=phys, src1=arg_reg))

    def emit_epilogue(self) -> None:
        n = self.alloc.nspills
        if n > 0:
            scratch = _SPILL_SCRATCH_A
            ins = _emit_opword(OPCODES["movi"], dst=scratch)
            ins.has_imm32 = True
            ins.imm32 = n * 8
            self.out.append(ins)
            self.out.append(_emit_opword(OPCODES["add"], dst=31, src1=31, src2=scratch))

    def gen(self) -> List[EmittedInstr]:
        self.emit_prologue()
        for ins in self.func.instrs:
            self.gen_instr(ins)
        return self.out

    def gen_instr(self, ins: Instr) -> None:
        op = ins.op
        if op == "label":
            self.labels[ins.label] = len(self.out)
            return
        if op == "movi":
            dstp, slot = self.dst_setup(ins.dst)
            e = _emit_opword(OPCODES["movi"], dst=dstp)
            e.has_imm32 = True
            e.imm32 = ins.imm & 0xFFFFFFFFFFFFFFFF
            self.out.append(e)
            self.write_dst(dstp, slot)
            return
        if op == "mov":
            s = self.load_src(ins.src1, _SPILL_SCRATCH_A)
            dstp, slot = self.dst_setup(ins.dst)
            self.out.append(_emit_opword(OPCODES["mov"], dst=dstp, src1=s))
            self.write_dst(dstp, slot)
            return
        if op in ("add", "sub", "mul", "div", "and", "or", "xor", "shl", "shr"):
            s1 = self.load_src(ins.src1, _SPILL_SCRATCH_A)
            s2 = self.load_src(ins.src2, _SPILL_SCRATCH_B)
            dstp, slot = self.dst_setup(ins.dst)
            self.out.append(_emit_opword(OPCODES[op], dst=dstp, src1=s1, src2=s2))
            self.write_dst(dstp, slot)
            return
        if op in ("not", "neg"):
            s1 = self.load_src(ins.src1, _SPILL_SCRATCH_A)
            dstp, slot = self.dst_setup(ins.dst)
            self.out.append(_emit_opword(OPCODES[op], dst=dstp, src1=s1))
            self.write_dst(dstp, slot)
            return
        if op == "cmp":
            s1 = self.load_src(ins.src1, _SPILL_SCRATCH_A)
            s2 = self.load_src(ins.src2, _SPILL_SCRATCH_B)
            self.out.append(_emit_opword(OPCODES["cmp"], src1=s1, src2=s2))
            return
        if op in _BRANCH_OPS:
            e = _emit_opword(OPCODES[op])
            e.has_imm32 = True
            e.imm32 = 0
            e.branch_label = ins.label
            self.out.append(e)
            return
        if op == "setarg":
            s = self.load_src(ins.src1, _SPILL_SCRATCH_A)
            target = ins.imm
            if s != target:
                self.out.append(_emit_opword(OPCODES["mov"], dst=target, src1=s))
            return
        if op == "syscall":
            self.out.append(_emit_opword(OPCODES["syscall"], imm9=ins.imm))
            return
        if op == "call":
            e = _emit_opword(OPCODES["call"], imm9=0)
            e.call_target = ins.extra
            self.out.append(e)
            dstp, slot = self.dst_setup(ins.dst)
            if dstp != 0:
                self.out.append(_emit_opword(OPCODES["mov"], dst=dstp, src1=0))
                self.write_dst(dstp, slot)
            return
        if op == "ret":
            s = self.load_src(ins.src1, _SPILL_SCRATCH_A)
            if s != 0:
                self.out.append(_emit_opword(OPCODES["mov"], dst=0, src1=s))
            self.emit_epilogue()
            self.out.append(_emit_opword(OPCODES["ret"]))
            return
        raise RuntimeError(f"unknown IR op {op}")


def _instr_size(e: EmittedInstr) -> int:
    return 8 if e.has_imm32 else 4


def _layout_pcs(instrs: List[EmittedInstr], base: int) -> int:
    pc = base
    for e in instrs:
        e.pc = pc
        pc += _instr_size(e)
    return pc


def _assign_variants(code_instrs: List[EmittedInstr], rng: random.Random) -> Tuple[Dict[int, List[int]], List[bytes]]:
    variant_map: Dict[int, List[int]] = {}
    for op_val in sorted(set(e.opcode for e in code_instrs)):
        n_variants = rng.randint(1, 3)
        ids = [op_val + v * 0x20 for v in range(n_variants) if (op_val + v * 0x20) <= 0xFF]
        variant_map[op_val] = ids
    mask_table: List[bytes] = [b"\x00\x00\x00\x00"] * 256
    for ids in variant_map.values():
        for vid in ids:
            mask = bytes([rng.randint(0, 255), rng.randint(0, 255), rng.randint(0, 255), 0])
            mask_table[vid] = mask
    return variant_map, mask_table


def _pick_variant(variant_map: Dict[int, List[int]], opcode: int, rng: random.Random) -> int:
    ids = variant_map.get(opcode)
    if not ids:
        return opcode
    return rng.choice(ids)


def generate(ir: IRProgram, rng: Optional[random.Random] = None) -> CodegenResult:
    """Generate ShadowVM code from the IR program."""
    if rng is None:
        rng = random.Random()
    result = CodegenResult()
    func_outs: List[FuncOut] = []
    all_instrs: List[EmittedInstr] = []
    offset = 0
    for i, f in enumerate(ir.funcs):
        alloc = allocate(f)
        gen = _FuncGen(f, alloc)
        instrs = gen.gen()
        pc_cursor = offset
        for e in instrs:
            e.pc = pc_cursor
            pc_cursor += _instr_size(e)
        label_pcs: Dict[str, int] = {}
        for name, idx in gen.labels.items():
            if idx < len(instrs):
                label_pcs[name] = instrs[idx].pc
            else:
                label_pcs[name] = pc_cursor
        for e in instrs:
            if e.branch_label is not None:
                tgt_pc = label_pcs[e.branch_label]
                e.imm32 = (tgt_pc - e.pc - 8) & 0xFFFFFFFF
        name_hash = _fnv1a(f.name.lower().encode("utf-8"))
        func_outs.append(FuncOut(name=f.name, name_hash=name_hash, offset=offset, instrs=instrs))
        all_instrs.extend(instrs)
        offset = pc_cursor
    result.func_index = {fo.name: i for i, fo in enumerate(func_outs)}
    for e in all_instrs:
        if e.call_target is not None:
            idx = result.func_index.get(e.call_target)
            if idx is None:
                raise RuntimeError(f"call to unknown function {e.call_target!r}")
            e.imm9 = idx & 0x1FF
    result.funcs = func_outs
    result.all_instrs = all_instrs
    result.code_size = offset
    variant_map, mask_table = _assign_variants(all_instrs, rng)
    for e in all_instrs:
        e.opcode = _pick_variant(variant_map, e.opcode, rng)
    result.variant_map = variant_map
    result.variant_mask = mask_table
    return result


def _fnv1a(data: bytes) -> int:
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def apply_masks(result: CodegenResult, kmaster: bytes) -> bytes:
    """Serialize code with variant masks and per-PC masks applied."""
    from .crypto import pc_mask
    out = bytearray()
    for e in result.all_instrs:
        word = _encode_opword(e.opcode, e.dst, e.src1, e.src2, e.imm9)
        mask_v = int.from_bytes(result.variant_mask[e.opcode], "little")
        word ^= mask_v
        pm = int.from_bytes(pc_mask(kmaster, e.pc), "little")
        word ^= pm
        out.extend(struct.pack("<I", word & 0xFFFFFFFF))
        if e.has_imm32:
            imm_pc = e.pc + 4
            pm2 = int.from_bytes(pc_mask(kmaster, imm_pc), "little")
            raw = e.imm32 & 0xFFFFFFFF
            out.extend(struct.pack("<I", raw ^ pm2))
    return bytes(out)


def pack_mask_table(result: CodegenResult) -> bytes:
    """Serialize the 256-entry variant mask table."""
    out = bytearray()
    for i in range(256):
        out.extend(result.variant_mask[i])
    return bytes(out)
