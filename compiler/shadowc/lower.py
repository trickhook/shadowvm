from __future__ import annotations

from typing import Dict, List

from . import ast as A
from .ir import Instr, IRFunc, IRProgram


_BIN_IR = {
    "+": "add",
    "-": "sub",
    "*": "mul",
    "/": "div",
    "&": "and",
    "|": "or",
    "^": "xor",
    "<<": "shl",
    ">>": "shr",
}

_CMP_SKIP = {
    "==": ("jne",),
    "!=": ("jeq",),
    "<":  ("jgt", "jeq"),
    ">":  ("jlt", "jeq"),
    "<=": ("jgt",),
    ">=": ("jlt",),
}

_CMP_TAKE = {
    "==": ("jeq",),
    "!=": ("jne",),
    "<":  ("jlt",),
    ">":  ("jgt",),
    "<=": ("jlt", "jeq"),
    ">=": ("jgt", "jeq"),
}


class LowerError(Exception):
    pass


class _FuncLower:
    def __init__(self, func: A.Func) -> None:
        self.func = func
        self.vreg = 0
        self.label_id = 0
        self.scopes: List[Dict[str, int]] = [{}]
        self.instrs: List[Instr] = []
        self.params: List[int] = []

    def new_vreg(self) -> int:
        v = self.vreg
        self.vreg += 1
        return v

    def new_label(self, hint: str = "L") -> str:
        self.label_id += 1
        return f"{hint}{self.label_id}"

    def push_scope(self) -> None:
        self.scopes.append({})

    def pop_scope(self) -> None:
        self.scopes.pop()

    def declare(self, name: str, vreg: int) -> None:
        self.scopes[-1][name] = vreg

    def lookup(self, name: str) -> int:
        for s in reversed(self.scopes):
            if name in s:
                return s[name]
        raise LowerError(f"unknown identifier {name!r}")

    def emit(self, op: str, dst: int = -1, src1: int = -1, src2: int = -1, imm: int = 0,
             label: str = None, extra: str = None) -> None:
        self.instrs.append(Instr(op=op, dst=dst, src1=src1, src2=src2, imm=imm, label=label, extra=extra))

    def lower(self) -> IRFunc:
        for p in self.func.params:
            v = self.new_vreg()
            self.declare(p, v)
            self.params.append(v)
        self.lower_block(self.func.body)
        if not self.instrs or self.instrs[-1].op != "ret":
            self.emit("movi", dst=self.new_vreg(), imm=0, extra="ret_default")
            r = self.instrs[-1].dst
            self.emit("ret", src1=r)
        return IRFunc(name=self.func.name, params=self.params, instrs=self.instrs, nvregs=self.vreg)

    def lower_block(self, b: A.Block) -> None:
        self.push_scope()
        for s in b.stmts:
            self.lower_stmt(s)
        self.pop_scope()

    def lower_stmt(self, s: A.Stmt) -> None:
        if isinstance(s, A.Let):
            v = self.lower_expr(s.expr)
            dst = self.new_vreg()
            self.emit("mov", dst=dst, src1=v)
            self.declare(s.name, dst)
            return
        if isinstance(s, A.Assign):
            v = self.lower_expr(s.expr)
            dst = self.lookup(s.name)
            self.emit("mov", dst=dst, src1=v)
            return
        if isinstance(s, A.If):
            self.lower_if(s)
            return
        if isinstance(s, A.While):
            self.lower_while(s)
            return
        if isinstance(s, A.Return):
            if s.expr is not None:
                v = self.lower_expr(s.expr)
            else:
                v = self.new_vreg()
                self.emit("movi", dst=v, imm=0)
            self.emit("ret", src1=v)
            return
        if isinstance(s, A.Syscall):
            arg_vregs = [self.lower_expr(a) for a in s.args]
            for i, v in enumerate(arg_vregs):
                self.emit("setarg", src1=v, imm=i)
            self.emit("syscall", imm=s.index)
            return
        if isinstance(s, A.ExprStmt):
            self.lower_expr(s.expr)
            return
        raise LowerError(f"unknown stmt {type(s).__name__}")

    def lower_if(self, s: A.If) -> None:
        else_lbl = self.new_label("Lelse")
        end_lbl = self.new_label("Lend")
        self.lower_cond_jump(s.cond, else_lbl)
        self.lower_block(s.then_block)
        self.emit("jmp", label=end_lbl)
        self.emit("label", label=else_lbl)
        if s.else_block is not None:
            self.lower_block(s.else_block)
        self.emit("label", label=end_lbl)

    def lower_while(self, s: A.While) -> None:
        top = self.new_label("Ltop")
        end = self.new_label("Lend")
        self.emit("label", label=top)
        self.lower_cond_jump(s.cond, end)
        self.lower_block(s.body)
        self.emit("jmp", label=top)
        self.emit("label", label=end)

    def lower_cond_jump(self, cond: A.Expr, false_lbl: str) -> None:
        if isinstance(cond, A.BinOp) and cond.op in _CMP_SKIP:
            l = self.lower_expr(cond.left)
            r = self.lower_expr(cond.right)
            self.emit("cmp", src1=l, src2=r)
            for jop in _CMP_SKIP[cond.op]:
                self.emit(jop, label=false_lbl)
            return
        if isinstance(cond, A.BinOp) and cond.op == "&&":
            self.lower_cond_jump(cond.left, false_lbl)
            self.lower_cond_jump(cond.right, false_lbl)
            return
        if isinstance(cond, A.BinOp) and cond.op == "||":
            true_lbl = self.new_label("Ltrue")
            self.lower_cond_jump_true(cond.left, true_lbl)
            self.lower_cond_jump(cond.right, false_lbl)
            self.emit("label", label=true_lbl)
            return
        v = self.lower_expr(cond)
        zero = self.new_vreg()
        self.emit("movi", dst=zero, imm=0)
        self.emit("cmp", src1=v, src2=zero)
        self.emit("jeq", label=false_lbl)

    def lower_cond_jump_true(self, cond: A.Expr, true_lbl: str) -> None:
        if isinstance(cond, A.BinOp) and cond.op in _CMP_TAKE:
            l = self.lower_expr(cond.left)
            r = self.lower_expr(cond.right)
            self.emit("cmp", src1=l, src2=r)
            for jop in _CMP_TAKE[cond.op]:
                self.emit(jop, label=true_lbl)
            return
        v = self.lower_expr(cond)
        zero = self.new_vreg()
        self.emit("movi", dst=zero, imm=0)
        self.emit("cmp", src1=v, src2=zero)
        self.emit("jne", label=true_lbl)

    def lower_expr(self, e: A.Expr) -> int:
        if isinstance(e, A.IntLit):
            dst = self.new_vreg()
            self.emit("movi", dst=dst, imm=e.value)
            return dst
        if isinstance(e, A.Ident):
            return self.lookup(e.name)
        if isinstance(e, A.UnOp):
            v = self.lower_expr(e.operand)
            dst = self.new_vreg()
            if e.op == "-":
                self.emit("neg", dst=dst, src1=v)
            elif e.op == "~":
                self.emit("not", dst=dst, src1=v)
            elif e.op == "!":
                zero = self.new_vreg()
                self.emit("movi", dst=zero, imm=0)
                self.emit("cmp", src1=v, src2=zero)
                one_lbl = self.new_label("Lone")
                end_lbl = self.new_label("Lend")
                self.emit("jeq", label=one_lbl)
                self.emit("movi", dst=dst, imm=0)
                self.emit("jmp", label=end_lbl)
                self.emit("label", label=one_lbl)
                self.emit("movi", dst=dst, imm=1)
                self.emit("label", label=end_lbl)
            else:
                raise LowerError(f"bad unary {e.op}")
            return dst
        if isinstance(e, A.BinOp):
            if e.op in _BIN_IR:
                l = self.lower_expr(e.left)
                r = self.lower_expr(e.right)
                dst = self.new_vreg()
                self.emit(_BIN_IR[e.op], dst=dst, src1=l, src2=r)
                return dst
            if e.op in _CMP_TAKE:
                l = self.lower_expr(e.left)
                r = self.lower_expr(e.right)
                dst = self.new_vreg()
                self.emit("cmp", src1=l, src2=r)
                true_lbl = self.new_label("Lcmpt")
                end_lbl = self.new_label("Lcmpe")
                for jop in _CMP_TAKE[e.op]:
                    self.emit(jop, label=true_lbl)
                self.emit("movi", dst=dst, imm=0)
                self.emit("jmp", label=end_lbl)
                self.emit("label", label=true_lbl)
                self.emit("movi", dst=dst, imm=1)
                self.emit("label", label=end_lbl)
                return dst
            if e.op == "&&":
                dst = self.new_vreg()
                false_lbl = self.new_label("Landf")
                end_lbl = self.new_label("Lande")
                self.lower_cond_jump(e.left, false_lbl)
                self.lower_cond_jump(e.right, false_lbl)
                self.emit("movi", dst=dst, imm=1)
                self.emit("jmp", label=end_lbl)
                self.emit("label", label=false_lbl)
                self.emit("movi", dst=dst, imm=0)
                self.emit("label", label=end_lbl)
                return dst
            if e.op == "||":
                dst = self.new_vreg()
                true_lbl = self.new_label("Lort")
                false_lbl = self.new_label("Lorf")
                end_lbl = self.new_label("Lore")
                self.lower_cond_jump_true(e.left, true_lbl)
                self.lower_cond_jump_true(e.right, true_lbl)
                self.emit("jmp", label=false_lbl)
                self.emit("label", label=true_lbl)
                self.emit("movi", dst=dst, imm=1)
                self.emit("jmp", label=end_lbl)
                self.emit("label", label=false_lbl)
                self.emit("movi", dst=dst, imm=0)
                self.emit("label", label=end_lbl)
                return dst
            raise LowerError(f"bad binop {e.op}")
        if isinstance(e, A.Call):
            arg_vregs = [self.lower_expr(a) for a in e.args]
            for i, v in enumerate(arg_vregs):
                self.emit("setarg", src1=v, imm=i)
            dst = self.new_vreg()
            self.emit("call", dst=dst, imm=0, extra=e.callee)
            return dst
        raise LowerError(f"unknown expr {type(e).__name__}")


def lower(prog: A.Program) -> IRProgram:
    """Lower an AST program to IR."""
    ir = IRProgram()
    for f in prog.funcs:
        ir.funcs.append(_FuncLower(f).lower())
    return ir
