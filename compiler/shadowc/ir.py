from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Instr:
    op: str
    dst: int = -1
    src1: int = -1
    src2: int = -1
    imm: int = 0
    label: Optional[str] = None
    extra: Optional[str] = None


@dataclass
class IRFunc:
    name: str
    params: List[int] = field(default_factory=list)
    instrs: List[Instr] = field(default_factory=list)
    nvregs: int = 0


@dataclass
class IRProgram:
    funcs: List[IRFunc] = field(default_factory=list)
