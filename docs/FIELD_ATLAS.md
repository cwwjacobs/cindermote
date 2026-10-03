# Field Atlas — Cindermote Component Map

Every component the doctrine names, where it runs, and whether it exists.
`cindermote kernel-laws` checks this table against the tree: a component marked
`implemented`, `reference` or `disabled` must name code that exists, and a
`removed` component must not.

Status values:

- `implemented` — wired into a shipped entry point and exercised by tests.
- `reference` — a decision-table model that is unit tested but **not** wired into
  any entry point. It documents intended behavior; it does not enforce anything today.
- `disabled` — a compatibility shim that exists only to deny.
- `removed` — no longer in the tree; kept so older documents stay readable.

| Component | Trust Zone | Status | Code | Description |
|---|---|---|---|---|
| `AgentProbeGuestAgent` | TAINTED_GUEST | implemented | `guest/agent_probe_agent.py` | Sacrificial LLM driver inside the Firecracker guest; reads the target `skill.md` and proposes actions through the broker. |
| `GuestEvidenceSealer` | TAINTED_GUEST | implemented | `agent_probe/evidence.py` | Encrypts the raw guest transcript (RFC 9180 HPKE wrap + libsodium secretstream) before it crosses to the host. |
| `AgentProbeBroker` | BROKERED_SEAM | implemented | `agent_probe/broker.py` | Host-side, content-blind broker: allows declared tools, hard-trips prohibited or undeclared ones. |
| `BrowserEgressProxy` | BROKERED_SEAM | implemented | `broker/browser_egress_proxy.py`, `broker/browser_egress_worker.py` | Privilege-separated CONNECT proxy with pinned DNS answers, peer checks and byte, connection and time budgets. |
| `FirecrackerRuntime` | TRUSTED_HOST | implemented | `mote/firecracker_runtime.py`, `agent_probe/firecracker_runtime.py` | Host-owned launch, teardown and externally verified purge of the microVM, worker, cgroup, network namespace and RAM jail. |
| `SignedReceipt` | TRUSTED_HOST | implemented | `agent_probe/receipt.py`, `agent_probe/contract.py`, `observer/receipt.py` | HMAC-SHA256 signed, metadata-only receipts with tamper detection and a stable exit-code mapping. |
| `EvidenceViewer` | QUARANTINE | implemented | `scripts/open-agent-probe-evidence.py` | Offline viewer: decrypts a sealed evidence bundle with the offline private key and escapes hostile text. |
| `CapabilityBroker` | BROKERED_SEAM | reference | `capability_brokers.py` | Declared-capability decision table (unknown capability resolves to COLLAPSE). Not consulted by agent-probe. |
| `CollapseMesh` | BROKERED_SEAM | reference | `collapse_mesh.py` | Cue-to-action table with a fail-closed default. Not consulted by agent-probe. |
| `GuestMCPController` | TAINTED_GUEST | disabled | `mcp_guest_controller.py` | Retired host-native MCP controller; every method raises `HostNativeExecutionDisabled`. |
| `ContainedModelHarness` | TAINTED_GUEST | removed | `contained_model_harness.py` | Replaced by `AgentProbeGuestAgent`. |
| `BurnPurgeEngine` | TRUSTED_HOST | removed | `burn_purge.py` | Replaced by the purge verification in `FirecrackerRuntime`. |
| `SealedReplayEngine` | TRUSTED_HOST | removed | `sealed_replay.py` | Replaced by `GuestEvidenceSealer`; the removed module did not implement authenticated encryption. |
| `QuarantinedReplayViewer` | QUARANTINE | removed | `quarantined_replay_viewer.py` | Replaced by `EvidenceViewer`. |
| `AshReceipt` | TRUSTED_HOST | removed | `ash_receipt.py` | Replaced by `SignedReceipt`. |
