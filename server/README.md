# shadowvm-server

Server component. Holds `K_master`, `K_sign`, `K_hmac[loader_id]` per registered loader build. Compiles + seals blobs; issues per-session envelopes bound to a specific loader instance and device fingerprint.

Endpoints: `/v1/compile`, `/v1/integrity/<blob_id>`, `/v1/session/challenge`, `/v1/session/complete`.

Author tokens and loader HMAC keys are managed via `shadowvm-server admin` CLI subcommands.
