from __future__ import annotations
import pathlib
import sys


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print("usage: svm_to_header.py <in.svm> <out.h> [symbol] [password]", file=sys.stderr)
        return 1
    inp = pathlib.Path(argv[1])
    out = pathlib.Path(argv[2])
    sym = argv[3] if len(argv) > 3 else "HELLO_SVM"
    pwd = argv[4] if len(argv) > 4 else "hunter2"
    data = inp.read_bytes()
    lines = [
        "#pragma once",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "",
        f"static const uint8_t {sym}[] = {{",
    ]
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        lines.append("    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",")
    lines.append("};")
    lines.append(f"static const size_t {sym}_LEN = sizeof({sym});")
    lines.append(f'static const char {sym}_PASSWORD[] = "{pwd}";')
    out.write_text("\n".join(lines) + "\n")
    print(f"wrote {out} ({len(data)} bytes, symbol={sym})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
