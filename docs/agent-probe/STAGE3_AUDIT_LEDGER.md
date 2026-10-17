# Stage 3 audit ledger

This is the audit checklist for comparing a real supported-host Road Walked
against Road Frozen. Unit tests are supporting evidence, not substitutes for the
host run.

One root run on the audited Void `6.18.57_1` host, `job-605f1a346b11ec76`
(local commit `0526265`), exercised the rows marked "one host run". It used a
deliberately invalid provider key: the guest made one model request, the
provider refused it, and the run ended `PROVIDER_FAILURE` /
`EVALUATION_INCOMPLETE`. It proposed no tools and reported no tokens, so it
does not cover the broker loop, hard-trip cutoff, or token telemetry rows.
See the [published evidence](../audits/evidence/2026-10-16/README.md).

An additional [October 17 live attempt](../audits/2026-10-17-agent-live-smoke.md),
`job-7e6efcfa037136e5`, reused a credential that passed a separate direct OpenAI
check. All 24 root preflight checks passed, and the real VM produced verified
receipts, complete sealed evidence, and verified cleanup. Its one guest request
attempt still ended `PROVIDER_FAILURE` / `EVALUATION_INCOMPLETE`, with no reported
tokens or tool proposals. The host metadata does not identify the guest's HTTP
status or transport error; this label alone does not prove a provider rejected
the key. Broker-loop, hard-trip, and positive guest token-telemetry host proof
therefore remain open.

| Requirement | Evidence required | Current source status |
|---|---|---|
| Firecracker-only execution | preflight receipt, VMM PID, Firecracker version, no namespace dispatch | Implemented; one host run |
| Guest semantic first touch | read-only job image hash, guest target-hash check, no host decode path | Implemented; one host run |
| Pinned model egress | proxy readiness, CONNECT authority, pinned peer, complete telemetry | Implemented through existing worker; one host run (one pinned-origin connection) |
| One-shot credential delivery | one bound vsock run frame, no env/argv/disk credential | Implemented; one host run with an invalid key |
| Iterative broker loop | ordered proposal metadata, decisions, task completion | Implemented and unit tested |
| Hard-trip cutoff | proxy revocation before trip response, no later model call | Implemented and component tested |
| Exact evidence crypto | RFC 9180 wrap, libsodium SecretStream, final tag, private-key decryption | Implemented and unit tested |
| Ciphertext before teardown | fsynced quarantine path timestamped before VMM teardown | Implemented; one host run (sealed evidence root verified; the public bundle does not show the fsync-before-teardown ordering) |
| Authentic receipt | envelope hash/HMAC verification before exit-code use | Implemented and unit tested |
| Witness-derived telemetry | guest usage metrics plus proxy byte/connection counters | Implemented; provider token reporting required for ALLOW; not yet shown on a host |
| External cleanup | worker/VMM reap, cgroup, netns, TAP, RAM jail removal | Reuses existing verified cleanup; one host run (`cleanup_status=VERIFIED`) |
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
