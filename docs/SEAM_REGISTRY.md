# Seam Registry — Path Crossings

Every path that crosses a trust boundary. Owners and brokers name components
from [FIELD_ATLAS.md](FIELD_ATLAS.md). `cindermote kernel-laws` fails if a
guest-to-host seam has no broker, any seam has no owner or is uninstrumented,
or a zone is not one of the declared trust zones.

| Seam ID | Source Zone | Target Zone | Owner | Broker | Instrumented | Triggered Action |
|---|---|---|---|---|---|---|
| `guest_mcp_event` | TAINTED_GUEST | TRUSTED_HOST | `GuestMCPController` | `CapabilityBroker` | Yes | Disabled: host-native MCP execution is denied before any process starts. |
| `guest_proposal_channel` | TAINTED_GUEST | TRUSTED_HOST | `AgentProbeGuestAgent` | `AgentProbeBroker` | Yes | Fixed action and argument-class enums plus SHA-256 hashes only; a prohibited or undeclared proposal hard-trips. |
| `guest_evidence_bundle` | TAINTED_GUEST | TRUSTED_HOST | `GuestEvidenceSealer` | `validate_bundle` | Yes | Ciphertext, hashes and counters only; structure, sequence and accounting are validated without the private key. |
| `guest_model_relay` | TAINTED_GUEST | EXTERNAL_PROVIDER | `AgentProbeGuestAgent` | `BrowserEgressProxy` | Yes | One pinned origin through CONNECT; pinned DNS and peer checks; byte, connection and time budgets. |
| `host_collapse_signal` | TRUSTED_HOST | TAINTED_GUEST | `FirecrackerRuntime` | None (Direct) | Yes | Egress revoked first, then the VMM process group and cgroup are killed and the RAM jail removed. |
| `quarantine_replay_read` | QUARANTINE | TRUSTED_HOST | `EvidenceViewer` | `decrypt_bundle` | Yes | Authenticated decryption with the offline private key; run on an isolated analyst machine. |
