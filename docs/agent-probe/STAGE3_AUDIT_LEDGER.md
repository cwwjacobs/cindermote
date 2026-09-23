# Stage 3 audit ledger

This is the audit checklist for comparing a real supported-host Road Walked
against Road Frozen. Unit tests are supporting evidence, not substitutes for the
host run.

| Requirement | Evidence required | Current source status |
|---|---|---|
| Firecracker-only execution | preflight receipt, VMM PID, Firecracker version, no namespace dispatch | Implemented; host E2E not run here |
| Guest semantic first touch | read-only job image hash, guest target-hash check, no host decode path | Implemented; host E2E pending |
| Pinned model egress | proxy readiness, CONNECT authority, pinned peer, complete telemetry | Implemented through existing worker; E2E pending |
| One-shot credential delivery | one bound vsock run frame, no env/argv/disk credential | Implemented; E2E pending |
| Iterative broker loop | ordered proposal metadata, decisions, task completion | Implemented and unit tested |
| Hard-trip cutoff | proxy revocation before trip response, no later model call | Implemented and component tested |
| Exact evidence crypto | RFC 9180 wrap, libsodium SecretStream, final tag, private-key decryption | Implemented and unit tested |
| Ciphertext before teardown | fsynced quarantine path timestamped before VMM teardown | Implemented; E2E pending |
| Authentic receipt | envelope hash/HMAC verification before exit-code use | Implemented and unit tested |
| Witness-derived telemetry | guest usage metrics plus proxy byte/connection counters | Implemented; provider token reporting required for ALLOW |
| External cleanup | worker/VMM reap, cgroup, netns, TAP, RAM jail removal | Reuses existing verified cleanup; E2E pending |
| No automatic promotion | ALLOW disposition remains HOLD | Implemented |

## Mandatory Stage 3 dispositions

- Any host-visible raw target/model/tool text: **DENY and failed boundary**.
- Any rootfs, runtime, endpoint, model, tool, budget, or schema drift:
  **RESCOPE_REQUIRED**.
- Missing token usage, ciphertext, proxy telemetry, or lifecycle evidence:
  **EVALUATION_INCOMPLETE**.
- Prohibited/undeclared proposal: **DENY**.
- Cleanup uncertainty: `cleanup_status=UNVERIFIED`, exit 6.
- Only a complete, exact, residue-free supported-host run may produce `ALLOW`.
