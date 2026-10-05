from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

from .ir import Instr, IRFunc


ARG_REGS = (0, 1, 2, 3, 4, 5)
VREG_POOL = tuple(range(6, 31))
SP_REG = 31


_DEF_OPS = {"movi", "mov", "add", "sub", "mul", "div", "and", "or", "xor",
            "shl", "shr", "not", "neg", "call"}
_USE1_OPS = {"mov", "not", "neg", "setarg", "ret"}
_USE1_USE2_OPS = {"add", "sub", "mul", "div", "and", "or", "xor",
                  "shl", "shr", "cmp"}


def _uses(instr: Instr) -> List[int]:
    uses: List[int] = []
    if instr.op in _USE1_USE2_OPS:
        uses.append(instr.src1)
        uses.append(instr.src2)
    elif instr.op in _USE1_OPS:
        uses.append(instr.src1)
    return [u for u in uses if u >= 0]


def _defines(instr: Instr) -> List[int]:
    if instr.op in _DEF_OPS and instr.dst >= 0:
        return [instr.dst]
    return []


@dataclass
class LiveInterval:
    vreg: int
    start: int
    end: int


@dataclass
class Allocation:
    reg_of: Dict[int, int] = field(default_factory=dict)
    spill_slot_of: Dict[int, int] = field(default_factory=dict)
    nspills: int = 0


def _compute_intervals(instrs: List[Instr]) -> List[LiveInterval]:
    first: Dict[int, int] = {}
    last: Dict[int, int] = {}
    for pc, ins in enumerate(instrs):
        for v in _defines(ins) + _uses(ins):
            if v not in first:
                first[v] = pc
            last[v] = pc
    label_pcs: Dict[str, int] = {}
    for pc, ins in enumerate(instrs):
        if ins.op == "label" and ins.label is not None:
            label_pcs[ins.label] = pc
    jump_ops = {"jmp", "jeq", "jne", "jlt", "jgt"}
    for pc, ins in enumerate(instrs):
        if ins.op in jump_ops and ins.label in label_pcs:
            tgt = label_pcs[ins.label]
            if tgt < pc:
                lo, hi = tgt, pc
                for v, lst in list(last.items()):
                    if first.get(v, 1 << 30) <= hi and lst >= lo and lst < hi:
                        last[v] = hi
    intervals = [LiveInterval(v, first[v], last[v]) for v in sorted(first.keys())]
    intervals.sort(key=lambda i: i.start)
    return intervals


def allocate(func: IRFunc) -> Allocation:
    """Linear-scan allocate vregs to physical registers."""
    alloc = Allocation()
    intervals = _compute_intervals(func.instrs)
    active: List[LiveInterval] = []
    free_regs: List[int] = list(VREG_POOL)
    for iv in intervals:
        new_active: List[LiveInterval] = []
        for a in active:
            if a.end < iv.start:
                free_regs.append(alloc.reg_of[a.vreg])
            else:
                new_active.append(a)
        active = new_active
        if free_regs:
            r = free_regs.pop(0)
            alloc.reg_of[iv.vreg] = r
            active.append(iv)
            active.sort(key=lambda x: x.end)
        else:
            spill_candidate = active[-1] if active else iv
            if spill_candidate.end > iv.end:
                alloc.reg_of[iv.vreg] = alloc.reg_of[spill_candidate.vreg]
                alloc.spill_slot_of[spill_candidate.vreg] = alloc.nspills
                alloc.nspills += 1
                del alloc.reg_of[spill_candidate.vreg]
                active = [a for a in active if a.vreg != spill_candidate.vreg]
                active.append(iv)
                active.sort(key=lambda x: x.end)
            else:
                alloc.spill_slot_of[iv.vreg] = alloc.nspills
                alloc.nspills += 1
    return alloc
