# Boundary Ledger — Truth Boundaries and Dispositions

## Classification Rules

- **TRUSTED**: Host orchestrator, `FirecrackerRuntime` teardown and purge verification, `AgentProbeBroker`, receipt signing (`SignedReceipt`).
- **UNTRUSTED / TAINTED**: The target `skill.md` and everything the guest derives from it: raw prompts, model completions, tool arguments and tool results. Guest MCP server processes are out of scope (host-native MCP execution is disabled).
- **BROKERED**: Model provider relay (pinned-origin CONNECT proxy), proposal channel (fixed enums and hashes).
- **SEALED**: Guest evidence ciphertext: a random content key wrapped to an offline X25519 key with RFC 9180 HPKE, records encrypted with libsodium secretstream. Readable only with the offline private key, through `EvidenceViewer`.
- **PROHIBITED**: Direct guest-to-host execution paths, unbrokered network access, raw host path access, static signing keys (refused by `sign_envelope`).

## Dispositions

Doctrine dispositions:

- `ADMIT`: Workload completed with zero policy violations and clean purge.
- `ADMIT_WITH_RESTRICTIONS`: Workload completed under restricted capability profile.
- `QUARANTINE`: Suspected policy breach; execution isolated and logged.
- `REJECT`: Capability request denied prior to execution.
- `INCONCLUSIVE`: Execution incomplete or unverified.
- `INFRASTRUCTURE_FAILED`: Host environment or hardware preflight failed (e.g. `/dev/kvm` missing).

agent-probe emits gate decisions instead: `ALLOW`, `DENY`, `RESCOPE_REQUIRED` and
`EVALUATION_INCOMPLETE`. `ALLOW` leaves the artifact on `HOLD`; nothing is promoted
automatically. See [agent-probe/ROAD_FROZEN.md](agent-probe/ROAD_FROZEN.md).
