# ShadowVM Blob Format

All multi-byte integers are little-endian.

## Layout

```
+-----------------------------+
|   Header (32 bytes)         |  cleartext
+-----------------------------+
|   Entry table               |  encrypted (part of body)
+-----------------------------+
|   Code section              |  encrypted
+-----------------------------+
|   Data section              |  encrypted
+-----------------------------+
|   Variant mask table        |  encrypted
+-----------------------------+
|   MAC (16 bytes)            |  cleartext
+-----------------------------+
```

Only the Header and the trailing MAC are cleartext. The entire body (entry table + code + data + mask table) is sealed by XChaCha20 + Poly1305.

## Header (32 bytes)

| offset | size | field       | value                                       |
|--------|------|-------------|---------------------------------------------|
| 0      | 4    | magic       | `0x53 0x56 0x4D 0x31` ("SVM1")              |
| 4      | 2    | version     | `0x0001`                                    |
| 6      | 2    | flags       | bit 0 = anti_debug, bit 1 = strip_names     |
| 8      | 4    | body_len    | length of encrypted body in bytes           |
| 12     | 4    | entry_off   | byte offset of entry table in body          |
| 16     | 4    | code_off    | byte offset of code section in body         |
| 20     | 4    | data_off    | byte offset of data section in body         |
| 24     | 4    | mask_off    | byte offset of variant mask table in body   |
| 28     | 4    | kdf_iters   | PBKDF2 iteration count (minimum 100000)     |

The 24-byte XChaCha20 nonce is derived at seal time as `BLAKE2s(magic || body_len)[0:24]`; it does not need to live in the header.

The 16-byte PBKDF2 salt is the first 16 bytes of the body, overwritten in-place after key derivation (so the salt lives inside the sealed region once the file is at rest). On open, the loader first does PBKDF2 with the still-encrypted salt bytes, which the sealer prearranged to be the same cleartext salt (sealed with a known keystream slice).

## Entry table

```
u32 count
repeated count times:
    u32 name_hash   // FNV-1a of the symbol name, lowercase
    u32 offset      // byte offset in code section
```

## Variant mask table

For each of the 256 opcode variants, 4 bytes of XOR mask applied to the following three operand bytes + imm9 low byte before decode. 256 * 4 = 1024 bytes.

## Sealing

1. Build body bytes in cleartext.
2. Derive `kmaster = PBKDF2-HMAC-SHA256(password, salt, kdf_iters, 32)`.
3. Derive `kauth = BLAKE2s(kmaster || "auth", 32)`.
4. nonce = BLAKE2s(magic || body_len, 24).
5. ciphertext = XChaCha20(kmaster, nonce, 0, body).
6. mac = Poly1305(kauth, header || ciphertext).
7. Write header || ciphertext || mac.

## Opening

1. Read header, validate magic + version.
2. Recompute nonce.
3. Derive kmaster, kauth as above.
4. Verify Poly1305 MAC in constant time; abort on mismatch.
5. Decrypt body with XChaCha20.
6. Overwrite salt bytes to zero in memory.

## Per-instruction stream

Instructions are additionally XORed with `BLAKE2s(kmaster || pc, 4)` before being treated as the raw ISA word. The compiler applies the same XOR before writing the word into the code section. This means a reader with only the sealed blob and even a leaked kmaster still has to compute per-PC BLAKE2s to decode each instruction, and the dispatcher derives the mask inline.
