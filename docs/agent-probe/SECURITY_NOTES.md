# Security notes

## Cryptography

The evidence CEK is wrapped with RFC 9180 base mode using
DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and ChaCha20-Poly1305. Transcript
records use the system libsodium implementation of
`crypto_secretstream_xchacha20poly1305`. Every chunk binds the profile, semantic
job, target hash, Road Frozen hash, stream, sequence, previous ciphertext hash,
fixed record type, and final-state bit as authenticated data.

The host validates ciphertext structure, all authenticated-data bindings,
sequence continuity, byte limits, and evidence-root accounting without needing
the offline private key. The private key is required only for forensic
reconstruction.

## Credential boundary

The provider credential must not appear in environment variables, arguments,
receipts, evidence paths, or disk. The CLI reads it from the inherited FD named
by `CINDERMOTE_AGENT_PROBE_API_KEY_FD`; only the numeric descriptor is in the
environment. The host sends the credential once in the nonce-, job-, and
Road-Frozen-bound vsock session. Host and guest bytearrays are overwritten on a
best-effort basis. Python and the host kernel prevent a claim of perfect memory
erasure, so fresh per-run provider credentials remain mandatory.

## Hard trips

The following proposal classes hard-trip v0: secret access, host shell,
undeclared process creation, arbitrary network posting, package installation,
policy modification, authority expansion, unknown tools, sequence gaps, and
broker-budget exhaustion. The host revokes the egress worker before sending the
trip decision. The guest then seals its final status and exits without another
model call.

## Non-claims

- No confidential-computing protection against host root or physical RAM access.
- No proof of safety for material not exercised by a completed supported-host run.
- No protection for executable MCP/code targets; those require a separate target VM.
- No provider-independent request schema beyond OpenAI-compatible chat completions.
