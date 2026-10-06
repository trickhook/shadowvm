import os
import secrets
import string
import sys

PLAINTEXT = {
    "URL_CHAL":   b"%s/v1/session/challenge",
    "URL_COMP":   b"%s/v1/session/complete",
    "URANDOM":    b"/dev/urandom",
    "FOPEN_RB":   b"rb",
    "JSON_CHAL":  b'{"blob_id":"%s","loader_id":"%s","device_fp":"%s","nonce_c":"%s"}',
    "JSON_COMP":  b'{"challenge_id":"%s","proof":"%s"}',
    "ATTEST_PIN": b"svm-attest|v1|",
    "K_CHAL_ID":  b"challenge_id",
    "K_NONCE_S":  b"nonce_s",
    "K_ENV_SE":   b"envelope_sealed",
    "K_ENV_SI":   b"envelope_sig",
    "K_SID":      b"session_id",
    "K_KEY":      b"key",
    "K_NONCE":    b"nonce",
    "K_EXPIRES":  b"expires",
    "L_URANDOM":  b"/dev/urandom",
    "L_RB":       b"rb",
    "L_AUTH":     b"auth",
    "PROC_STAT":  b"/proc/self/status",
    "PROC_MAPS":  b"/proc/self/maps",
    "PROC_RE":    b"re",
    "TRACER":     b"TracerPid:",
    "RXP":        b"r-xp",
}

def pick_soname() -> str:
    alpha = string.ascii_lowercase
    stem = "".join(secrets.choice(alpha) for _ in range(secrets.choice([5, 6, 7])))
    return f"lib{stem}.so"

def emit(out_header: str, out_cmake: str) -> None:
    master = secrets.token_bytes(32)
    soname = pick_soname()
    strings_all = dict(PLAINTEXT)
    strings_all["SONAME"] = soname.encode("ascii")

    lines = []
    lines.append("#ifndef SHADOWVM_OBF_STRINGS_H")
    lines.append("#define SHADOWVM_OBF_STRINGS_H")
    lines.append("")
    lines.append("#include <stdint.h>")
    lines.append("")
    lines.append("static const uint8_t SVM_OBF_MASTER[32] = {")
    lines.append("    " + ", ".join(f"0x{b:02x}" for b in master))
    lines.append("};")
    lines.append("")
    for name, plain in strings_all.items():
        pad = secrets.token_bytes(len(plain))
        ct = bytes(p ^ k for p, k in zip(plain, pad))
        pad_x = bytes(pad[i] ^ master[i % 32] for i in range(len(pad)))
        lines.append(f"static const uint8_t OBF_{name}[] = {{ {', '.join(f'0x{b:02x}' for b in ct)} }};")
        lines.append(f"static const uint8_t PAD_{name}[] = {{ {', '.join(f'0x{b:02x}' for b in pad_x)} }};")
        lines.append(f"#define OBF_{name}_LEN {len(plain)}")
        lines.append("")
    lines.append("#endif")

    os.makedirs(os.path.dirname(out_header), exist_ok=True)
    with open(out_header, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines))

    os.makedirs(os.path.dirname(out_cmake), exist_ok=True)
    with open(out_cmake, "w", encoding="utf-8", newline="\n") as f:
        f.write(f'set(SVM_OBF_SONAME "{soname}" CACHE INTERNAL "")\n')

if __name__ == "__main__":
    out_header = sys.argv[1] if len(sys.argv) > 1 else "obf_strings.h"
    out_cmake = sys.argv[2] if len(sys.argv) > 2 else "obf_soname.cmake"
    emit(out_header, out_cmake)
