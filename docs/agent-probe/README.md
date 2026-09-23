# Cindermote agent-probe v0

`agent-probe` is a Firecracker-only semantic first-touch profile for one passive
`skill.md`. A disposable API-powered LLM inside the microVM reads the target,
performs a fixed synthetic task, and proposes actions through a content-blind
host broker. There is no namespace fallback and no automatic promotion.

## End-to-end path

```text
operator-approved target bytes
  -> host hashes and copies opaque bytes to read-only job.ext4
  -> Firecracker guest reads skill.md first
  -> guest constructs task + BOLO prompt
  -> guest calls one pinned OpenAI-compatible HTTPS endpoint
     through Cindermote's privilege-separated CONNECT proxy
  -> guest sends only fixed proposal enums + hashes to host broker
  -> host allows, denies, or hard-trips
  -> guest encrypts raw prompt/response/tool evidence before host crossing
  -> ciphertext is persisted before VM teardown
  -> host reaps proxy/VMM/cgroup/network/jail
  -> Road Walked, Road Diff, and authenticated receipt are persisted
```

The ordinary host never receives raw target text, model output, tool arguments,
or tool results from the production guest protocol. It necessarily handles the
operator-supplied target bytes opaquely for hashing and disk-image transport,
and it necessarily handles the fresh provider credential long enough to send it
once over the bound vsock control channel. Host-root cryptographic blindness is
not claimed.

## Frozen v0 scope

- passive `skill.md` only;
- one Firecracker microVM;
- one pinned OpenAI-compatible endpoint and model;
- fixed synthetic task and BOLO brief;
- fixed primary, BOLO, and prohibited tool identifiers;
- HTTPS only through the existing pinned-origin CONNECT proxy;
- RFC 9180 HPKE base mode CEK wrapping;
- actual libsodium `crypto_secretstream_xchacha20poly1305` transcript framing;
- encrypted evidence quarantine;
- no MCP, browser ingestion, package installation, dynamic tools, or promotion.

See [RUNBOOK.md](RUNBOOK.md) for host preparation and execution, and
[STAGE3_AUDIT_LEDGER.md](STAGE3_AUDIT_LEDGER.md) for the frozen audit checklist.
