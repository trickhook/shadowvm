# ShadowVM Crypto

All primitives are self-contained; no OpenSSL/mbedTLS dependency so the native loader stays small and inlinable.

## Primitives

- **XChaCha20** stream cipher, 256-bit key, 192-bit nonce. Reference: RFC 8439 (ChaCha20) + draft-irtf-cfrg-xchacha for HChaCha20 subkey derivation.
- **Poly1305** 128-bit tag over `header || ciphertext`.
- **PBKDF2-HMAC-SHA256** for password → key.
- **BLAKE2s** for short keyed derivations (nonce from header, per-PC mask).
- **FNV-1a 32-bit** for symbol name hashing in the entry table.

## Test vectors

All implementations must round-trip the following cases:

### XChaCha20

- key = `0x80 0x81 .. 0x9f`
- nonce = `0x40 0x41 .. 0x57`
- counter = 1
- plaintext = ASCII "The dhole (pronounced \"dole\") is also known as the Asiatic wild dog..."
- expected first 16 bytes of ciphertext: `7d 0a 2e 6b 7f 7c 65 a2 36 54 26 30 29 4e 06 3b`

(reference vector from draft-irtf-cfrg-xchacha)

### Poly1305

- key = `0x85 0xd6 .. 0xb8` (32 bytes)
- msg = `"Cryptographic Forum Research Group"`
- tag = `a8 06 1d c1 30 51 36 c6 c2 2b 8b af 0c 01 27 a9`

### PBKDF2-HMAC-SHA256

- password = "password"
- salt = "salt"
- iterations = 4096
- dkLen = 32
- expected = `c5 e4 78 d5 92 88 c8 41 aa 53 0d b6 84 5c 4c 8d 96 28 93 a0 01 ce 4e 11 a4 96 38 73 aa 98 13 4a`

### BLAKE2s

- key = `""`
- input = `""`
- output = `69 21 7a 30 79 90 80 94 e1 11 21 d0 42 35 4a 7c 1f 55 b6 48 2c a1 a5 1e 1b 25 0d fd 1e d0 ee f9`

### FNV-1a 32-bit

- `"hello"` → `0x4f9f2cab`

## API contracts

See `vm/include/shadowvm_crypto.h` and `compiler/shadowc/crypto.py`.
