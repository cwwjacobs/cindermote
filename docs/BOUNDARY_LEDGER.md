# Boundary Ledger — Truth Boundaries and Dispositions

## Classification Rules

- **TRUSTED**: Host orchestrator, `BurnPurgeEngine`, `CapabilityBroker`, `AshReceipt` signing.
- **UNTRUSTED / TAINTED**: Guest MCP server process, raw tool descriptions, raw schemas, raw prompt text, raw model completions, raw tool results.
- **BROKERED**: Model provider relay, stdio event stream.
- **SEALED**: Replay ciphertext encrypted locally with per-run random key.
- **PROHIBITED**: Direct guest-to-host execution paths, unbrokered network access, raw host path access, static signing keys.

## Dispositions

- `ADMIT`: Workload completed with zero policy violations and clean purge.
- `ADMIT_WITH_RESTRICTIONS`: Workload completed under restricted capability profile.
- `QUARANTINE`: Suspected policy breach; execution isolated and logged.
- `REJECT`: Capability request denied prior to execution.
- `INCONCLUSIVE`: Execution incomplete or unverified.
- `INFRASTRUCTURE_FAILED`: Host environment or hardware preflight failed (e.g. `/dev/kvm` missing).
