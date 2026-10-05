from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Union


@dataclass
class Node:
    line: int = 0
    col: int = 0


@dataclass
class IntLit(Node):
    value: int = 0


@dataclass
class Ident(Node):
    name: str = ""


@dataclass
class BinOp(Node):
    op: str = ""
    left: "Expr" = None
    right: "Expr" = None


@dataclass
class UnOp(Node):
    op: str = ""
    operand: "Expr" = None


@dataclass
class Call(Node):
    callee: str = ""
    args: List["Expr"] = field(default_factory=list)


Expr = Union[IntLit, Ident, BinOp, UnOp, Call]


@dataclass
class Let(Node):
    name: str = ""
    expr: Expr = None


@dataclass
class Assign(Node):
    name: str = ""
    expr: Expr = None


@dataclass
class If(Node):
    cond: Expr = None
    then_block: "Block" = None
    else_block: Optional["Block"] = None


@dataclass
class While(Node):
    cond: Expr = None
    body: "Block" = None


@dataclass
class Return(Node):
    expr: Optional[Expr] = None


@dataclass
class Syscall(Node):
    index: int = 0
    args: List[Expr] = field(default_factory=list)


@dataclass
class ExprStmt(Node):
    expr: Expr = None


Stmt = Union[Let, Assign, If, While, Return, Syscall, ExprStmt]


@dataclass
class Block(Node):
    stmts: List[Stmt] = field(default_factory=list)


@dataclass
class Func(Node):
    name: str = ""
    params: List[str] = field(default_factory=list)
    body: Block = None


@dataclass
class Program(Node):
    funcs: List[Func] = field(default_factory=list)
