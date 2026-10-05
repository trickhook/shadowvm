# shadowvm

Server-sealed native code obfuscator. Lifts routines into a sealed VM so static analysis sees only an opaque dispatch loop over encrypted bytecode. Register ISA, polymorphic handlers, per-PC stream masking, XChaCha20 + Poly1305 blobs keyed by PBKDF2.

Keys and integrity live on the server. The author never sees them. The runtime unseals a per-session envelope bound to a specific loader build and device fingerprint, and the envelope is signed by the server.

## pieces

| path                | role                                                              |
|---------------------|-------------------------------------------------------------------|
| `spec/`             | ISA, blob format, crypto spec, server/client protocol             |
| `vm/`               | native runtime: dispatcher, handlers, crypto, loader, attestation |
| `compiler/shadowc/` | thin CLI client: submit source, fetch sealed blob                 |
| `server/`           | FastAPI service: holds master keys, compiles, seals, attests      |
| `tools/`            | admin + inspection helpers                                        |
| `examples/`         | end-to-end samples                                                |
| `tests/`            | round-trip and vector tests                                       |

## flow

```
author          server (holds K_master, K_sign, K_hmac)      end user
  |                        |                                    |
  | POST /v1/compile       |                                    |
  |----------------------->|                                    |
  |                        |  compile + seal with K_master      |
  |                        |  store canonical body + MAC        |
  | <blob_id, sealed blob> |                                    |
  |<-----------------------|                                    |
  | distribute blob + loader to end user                        |
  |-------------------------------------------------------------|
  |                        |  POST /v1/session/challenge        |
  |                        |<-----------------------------------|
  |                        |                                    |
  |                        |  POST /v1/session/complete         |
  |                        |<-----------------------------------|
  |                        |  verify HMAC proof                 |
  |                        |  derive K_session, sign envelope   |
  |                        |----------------------------------->|
  |                        |                                    | decrypt in RAM
  |                        |                                    | run
```

## build

Native runtime (Android arm64-v8a, NDK r30):

```
cmake -S vm -B vm/build \
  -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-26
cmake --build vm/build
```

Server:

```
pip install -e server
cp server/.env.example server/.env
shadowvm-server admin init
shadowvm-server run
```

Client CLI:

```
pip install -e compiler
shadowc submit examples/hello.sdl \
    --server https://svm.local:8443 --token "$SVM_TOKEN" \
    --loader lid_... -o hello.svm
```

## status

alpha. ISA v1 frozen. Protocol v1 frozen.
