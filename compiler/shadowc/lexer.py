from __future__ import annotations

from dataclasses import dataclass
from typing import List


KEYWORDS = {
    "fn", "let", "if", "else", "while", "return", "syscall",
}


_PUNCT_MULTI = ("==", "!=", "<=", ">=", "<<", ">>", "&&", "||")
_PUNCT_SINGLE = "(){},;=+-*/%&|^~!<>"


@dataclass
class Token:
    kind: str
    value: str
    line: int
    col: int


class LexError(Exception):
    pass


def tokenize(src: str) -> List[Token]:
    """Lex source into a list of tokens."""
    tokens: List[Token] = []
    i = 0
    line = 1
    col = 1
    n = len(src)
    while i < n:
        c = src[i]
        if c == "\n":
            i += 1
            line += 1
            col = 1
            continue
        if c in " \t\r":
            i += 1
            col += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            start_line, start_col = line, col
            i += 2
            col += 2
            while i + 1 < n and not (src[i] == "*" and src[i + 1] == "/"):
                if src[i] == "\n":
                    line += 1
                    col = 1
                else:
                    col += 1
                i += 1
            if i + 1 >= n:
                raise LexError(f"line {start_line} col {start_col}: unterminated block comment")
            i += 2
            col += 2
            continue
        if c.isdigit():
            start_col = col
            j = i
            if c == "0" and i + 1 < n and src[i + 1] in ("x", "X"):
                j += 2
                while j < n and (src[j].isdigit() or src[j].lower() in "abcdef_"):
                    j += 1
                raw = src[i:j].replace("_", "")
                value = int(raw, 16)
            else:
                while j < n and (src[j].isdigit() or src[j] == "_"):
                    j += 1
                raw = src[i:j].replace("_", "")
                value = int(raw, 10)
            tokens.append(Token("INT", str(value), line, start_col))
            col += j - i
            i = j
            continue
        if c.isalpha() or c == "_":
            start_col = col
            j = i
            while j < n and (src[j].isalnum() or src[j] == "_"):
                j += 1
            word = src[i:j]
            kind = "KEYWORD" if word in KEYWORDS else "IDENT"
            tokens.append(Token(kind, word, line, start_col))
            col += j - i
            i = j
            continue
        if i + 1 < n and src[i:i + 2] in _PUNCT_MULTI:
            tokens.append(Token("PUNCT", src[i:i + 2], line, col))
            i += 2
            col += 2
            continue
        if c in _PUNCT_SINGLE:
            tokens.append(Token("PUNCT", c, line, col))
            i += 1
            col += 1
            continue
        raise LexError(f"line {line} col {col}: unexpected character {c!r}")
    tokens.append(Token("EOF", "", line, col))
    return tokens
