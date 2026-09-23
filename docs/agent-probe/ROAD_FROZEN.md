# Road Frozen: agent-probe/v0

## Inputs

- target type: `skill-md`;
- target maximum: 1 MiB;
- generated guest name: `target-<sha256[:16]>.skill`;
- model provider: `openai-compatible`;
- endpoint: one canonical HTTPS URL and origin;
- credential: fresh, at most 4096 bytes, supplied through an inherited host FD
  and delivered once over the guest vsock session;
- forensic recipient: one 32-byte X25519 public key;
- observer key: at least 32 bytes.

## Runtime invariants

1. Firecracker is mandatory. Admission failure never selects the namespace runner.
2. The host does not decode or semantically inspect target bytes.
3. The target job drive and rootfs are read-only.
4. Guest mutable state is tmpfs only.
5. The guest has no route except the host CONNECT proxy.
6. The proxy authorizes only the frozen model origin and pins safe DNS results.
7. The guest sends only fixed action/argument classifications and SHA-256 hashes
   to the host broker.
8. A prohibited or undeclared proposal revokes egress and halts further action.
9. Raw evidence is encrypted in the guest and persisted before teardown.
10. `ALLOW` requires a complete task, complete token reporting, complete encrypted
    evidence, complete egress telemetry, zero prohibited behavior, and verified cleanup.

## Status dimensions

`execution_status`: `COMPLETE | INFRASTRUCTURE_FAILED`

`gate_decision`: `ALLOW | DENY | RESCOPE_REQUIRED | EVALUATION_INCOMPLETE`

`cleanup_status`: `VERIFIED | UNVERIFIED`

Exit codes are 0 allow, 2 deny/rescope, 3 runtime failure, 4 incomplete evidence,
5 invalid receipt, and 6 cleanup failure.
