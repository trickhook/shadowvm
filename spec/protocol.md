# ShadowVM Protocol

Three parties:

- **Author** (operator): submits source, receives sealed blob + `blob_id`. Never touches master keys.
- **Server**: holds all master keys, performs compile + seal, enforces integrity, issues per-session wrapped keys.
- **Client runtime**: ships inside the end-user application. At open time, performs attestation and receives a session-wrapped key.

The master key lives only on the server. The author sees ciphertext. The client sees a per-session envelope that only decrypts in that device + session.

## Keys and identities

| key                   | holder   | lifetime         | purpose                            |
|-----------------------|----------|------------------|------------------------------------|
| `K_master[loader_id]` | server   | long-term, HSM   | PBKDF2 base for sealing blobs      |
| `K_sign` (Ed25519)    | server   | long-term        | signs session envelopes            |
| `K_sign_pub`          | client   | compiled-in      | verifies session envelopes         |
| `K_api[account]`      | both     | rotated          | bearer token for author API calls  |
| `K_hmac[loader_id]`   | both     | rotated per build| client proof-of-loader HMAC key    |
| `K_session`           | derived  | one session      | XChaCha20 key for in-memory blob   |

`K_hmac[loader_id]` is injected into the loader at build time by the server during a signed build job, so the author never has it in cleartext either; the server also keeps a copy indexed by `loader_id`.

## Author flow

### `POST /v1/compile`

Request:
```
Authorization: Bearer <api_token>
Content-Type: application/json
{
  "source": "<DSL source>",
  "target_loader_id": "lid_...",
  "symbols":   ["main", "step"],
  "flags":     { "anti_debug": true, "strip_names": true }
}
```

Response (200):
```
{
  "blob_id":   "blb_...",
  "blob_sha256": "...",
  "sealed_blob": "<base64 of header+body+mac>",
  "created_at": 1733500000
}
```

- Server derives `K_master[target_loader_id]` from the KMS.
- Server runs the compiler, builds the body, seals it with XChaCha20 + Poly1305.
- Server stores (`blob_id` → `K_master`, `blob_sha256`, canonical copy of sealed body, metadata).
- Author gets the sealed blob to distribute. Without a valid session envelope later, the blob is unopenable.

### `GET /v1/integrity/<blob_id>`

Server recomputes MAC against its stored canonical copy and the master key, confirms no drift, returns:
```
{ "ok": true, "blob_sha256": "...", "verified_at": 1733500000 }
```

The author cannot forge this because the author has no access to `K_master`.

## Client flow

### Phase 1 - loader attestation challenge

```
POST /v1/session/challenge
{
  "blob_id":   "blb_...",
  "loader_id": "lid_...",
  "device_fp": "<32B hex>",
  "nonce_c":   "<16B random>"
}
```

Server replies:
```
{
  "challenge_id": "chg_...",
  "nonce_s":      "<16B hex>",
  "ttl_ms":       10000
}
```

The server records (`challenge_id`, `loader_id`, `blob_id`, `nonce_s`, `device_fp`, deadline).

### Phase 2 - loader proof

Client computes:
```
proof = HMAC-SHA256(K_hmac[loader_id],
                    "svm-attest|v1|" || blob_id || loader_id ||
                    device_fp || nonce_c || nonce_s)
```

```
POST /v1/session/complete
{
  "challenge_id": "chg_...",
  "proof":        "<32B hex>"
}
```

Server:
- Looks up challenge; rejects if expired, mismatched, or replayed.
- Recomputes expected proof with its own copy of `K_hmac[loader_id]`.
- On match, derives `K_session = BLAKE2s(K_master || challenge_id || device_fp, 32)`.
- Builds `envelope`:
  ```
  envelope_body = {
    "session_id": "ses_...",
    "key":        "<32B K_session>",
    "nonce":      "<24B XChaCha20 nonce for the blob>",
    "expires":    <unix_ms>
  }
  ```
- Encrypts `envelope_body` with ephemeral XChaCha20 using key = `BLAKE2s(K_hmac[loader_id] || nonce_c || nonce_s, 32)` so only this exact loader instance can open it.
- Signs the sealed envelope with Ed25519 `K_sign`.

Response:
```
{
  "session_id":        "ses_...",
  "envelope_sealed":   "<base64>",
  "envelope_sig":      "<64B Ed25519 signature>",
  "expires":           1733500120000
}
```

Client:
- Verifies `envelope_sig` against compiled-in `K_sign_pub`.
- Derives the same ephemeral key from `K_hmac` and the two nonces.
- Decrypts the envelope, extracts `K_session` and the XChaCha20 nonce.
- Uses them to decrypt the sealed blob in memory and run it.
- Zeroes `K_session`, `K_hmac`, and the ephemeral key on process exit or session expiry.

If `envelope_sig` fails, if `K_hmac` is wrong, or if the device_fp drifts, no key material is ever revealed in cleartext.

## Rate limiting and revocation

- Per-account quota on `/v1/compile`.
- Per-(loader_id, device_fp) quota on session issuance; sudden spikes trip a block.
- Server can revoke `K_hmac[loader_id]`, which permanently kills a build.
- Server can revoke `blob_id`, which refuses all future sessions for that artifact.

## Transport

TLS 1.3 required. HMAC proofs and envelope signatures still protect against TLS-MITM edge cases where a corporate proxy or compromised CA sits between client and server.
