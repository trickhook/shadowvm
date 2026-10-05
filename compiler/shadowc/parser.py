from __future__ import annotations

from typing import List, Optional

from .lexer import Token, tokenize
from . import ast as A


class ParseError(Exception):
    pass


class Parser:
    """Recursive-descent parser for the shadowc DSL."""

    def __init__(self, tokens: List[Token]) -> None:
        self.toks = tokens
        self.pos = 0

    def peek(self, k: int = 0) -> Token:
        return self.toks[self.pos + k]

    def advance(self) -> Token:
        t = self.toks[self.pos]
        self.pos += 1
        return t

    def accept(self, kind: str, value: Optional[str] = None) -> Optional[Token]:
        t = self.peek()
        if t.kind == kind and (value is None or t.value == value):
            return self.advance()
        return None

    def expect(self, kind: str, value: Optional[str] = None) -> Token:
        t = self.peek()
        if t.kind == kind and (value is None or t.value == value):
            return self.advance()
        want = f"{kind}{'(' + value + ')' if value else ''}"
        raise ParseError(
            f"line {t.line} col {t.col}: expected {want}, got {t.kind}({t.value!r})"
        )

    def parse_program(self) -> A.Program:
        funcs = []
        while self.peek().kind != "EOF":
            funcs.append(self.parse_func())
        return A.Program(funcs=funcs)

    def parse_func(self) -> A.Func:
        kw = self.expect("KEYWORD", "fn")
        name_tok = self.expect("IDENT")
        self.expect("PUNCT", "(")
        params: List[str] = []
        if self.peek().value != ")":
            params.append(self.expect("IDENT").value)
            while self.accept("PUNCT", ","):
                params.append(self.expect("IDENT").value)
        self.expect("PUNCT", ")")
        body = self.parse_block()
        return A.Func(line=kw.line, col=kw.col, name=name_tok.value, params=params, body=body)

    def parse_block(self) -> A.Block:
        open_tok = self.expect("PUNCT", "{")
        stmts = []
        while self.peek().value != "}":
            stmts.append(self.parse_stmt())
        self.expect("PUNCT", "}")
        return A.Block(line=open_tok.line, col=open_tok.col, stmts=stmts)

    def parse_stmt(self) -> A.Stmt:
        t = self.peek()
        if t.kind == "KEYWORD" and t.value == "let":
            return self.parse_let()
        if t.kind == "KEYWORD" and t.value == "if":
            return self.parse_if()
        if t.kind == "KEYWORD" and t.value == "while":
            return self.parse_while()
        if t.kind == "KEYWORD" and t.value == "return":
            return self.parse_return()
        if t.kind == "KEYWORD" and t.value == "syscall":
            return self.parse_syscall()
        if t.kind == "IDENT" and self.peek(1).kind == "PUNCT" and self.peek(1).value == "=":
            return self.parse_assign()
        expr = self.parse_expr()
        self.expect("PUNCT", ";")
        return A.ExprStmt(line=t.line, col=t.col, expr=expr)

    def parse_let(self) -> A.Let:
        kw = self.expect("KEYWORD", "let")
        name = self.expect("IDENT").value
        self.expect("PUNCT", "=")
        expr = self.parse_expr()
        self.expect("PUNCT", ";")
        return A.Let(line=kw.line, col=kw.col, name=name, expr=expr)

    def parse_assign(self) -> A.Assign:
        name_tok = self.expect("IDENT")
        self.expect("PUNCT", "=")
        expr = self.parse_expr()
        self.expect("PUNCT", ";")
        return A.Assign(line=name_tok.line, col=name_tok.col, name=name_tok.value, expr=expr)

    def parse_if(self) -> A.If:
        kw = self.expect("KEYWORD", "if")
        cond = self.parse_expr()
        then_block = self.parse_block()
        else_block = None
        if self.accept("KEYWORD", "else"):
            else_block = self.parse_block()
        return A.If(line=kw.line, col=kw.col, cond=cond, then_block=then_block, else_block=else_block)

    def parse_while(self) -> A.While:
        kw = self.expect("KEYWORD", "while")
        cond = self.parse_expr()
        body = self.parse_block()
        return A.While(line=kw.line, col=kw.col, cond=cond, body=body)

    def parse_return(self) -> A.Return:
        kw = self.expect("KEYWORD", "return")
        expr = None
        if self.peek().value != ";":
            expr = self.parse_expr()
        self.expect("PUNCT", ";")
        return A.Return(line=kw.line, col=kw.col, expr=expr)

    def parse_syscall(self) -> A.Syscall:
        kw = self.expect("KEYWORD", "syscall")
        idx_tok = self.expect("INT")
        self.expect("PUNCT", "(")
        args: List[A.Expr] = []
        if self.peek().value != ")":
            args.append(self.parse_expr())
            while self.accept("PUNCT", ","):
                args.append(self.parse_expr())
        self.expect("PUNCT", ")")
        self.expect("PUNCT", ";")
        return A.Syscall(line=kw.line, col=kw.col, index=int(idx_tok.value), args=args)

    def parse_expr(self) -> A.Expr:
        return self.parse_logic()

    def parse_logic(self) -> A.Expr:
        left = self.parse_comparison()
        while self.peek().kind == "PUNCT" and self.peek().value in ("&&", "||"):
            op = self.advance().value
            right = self.parse_comparison()
            left = A.BinOp(line=left.line, col=left.col, op=op, left=left, right=right)
        return left

    def parse_comparison(self) -> A.Expr:
        left = self.parse_additive()
        while self.peek().kind == "PUNCT" and self.peek().value in ("==", "!=", "<", ">", "<=", ">="):
            op = self.advance().value
            right = self.parse_additive()
            left = A.BinOp(line=left.line, col=left.col, op=op, left=left, right=right)
        return left

    def parse_additive(self) -> A.Expr:
        left = self.parse_multiplicative()
        while self.peek().kind == "PUNCT" and self.peek().value in ("+", "-", "|", "^"):
            op = self.advance().value
            right = self.parse_multiplicative()
            left = A.BinOp(line=left.line, col=left.col, op=op, left=left, right=right)
        return left

    def parse_multiplicative(self) -> A.Expr:
        left = self.parse_unary()
        while self.peek().kind == "PUNCT" and self.peek().value in ("*", "/", "&", "<<", ">>"):
            op = self.advance().value
            right = self.parse_unary()
            left = A.BinOp(line=left.line, col=left.col, op=op, left=left, right=right)
        return left

    def parse_unary(self) -> A.Expr:
        t = self.peek()
        if t.kind == "PUNCT" and t.value in ("-", "~", "!"):
            op = self.advance().value
            operand = self.parse_unary()
            return A.UnOp(line=t.line, col=t.col, op=op, operand=operand)
        return self.parse_primary()

    def parse_primary(self) -> A.Expr:
        t = self.peek()
        if t.kind == "INT":
            self.advance()
            return A.IntLit(line=t.line, col=t.col, value=int(t.value))
        if t.kind == "IDENT":
            self.advance()
            if self.accept("PUNCT", "("):
                args: List[A.Expr] = []
                if self.peek().value != ")":
                    args.append(self.parse_expr())
                    while self.accept("PUNCT", ","):
                        args.append(self.parse_expr())
                self.expect("PUNCT", ")")
                return A.Call(line=t.line, col=t.col, callee=t.value, args=args)
            return A.Ident(line=t.line, col=t.col, name=t.value)
        if t.kind == "PUNCT" and t.value == "(":
            self.advance()
            e = self.parse_expr()
            self.expect("PUNCT", ")")
            return e
        raise ParseError(f"line {t.line} col {t.col}: unexpected token {t.kind}({t.value!r})")


def parse(src: str) -> A.Program:
    """Parse DSL source into an AST."""
    return Parser(tokenize(src)).parse_program()
