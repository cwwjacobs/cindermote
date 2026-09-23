# Seam Registry — Path Crossings

| Seam ID | Source Zone | Target Zone | Owner | Broker | Instrumented | Triggered Action |
|---|---|---|---|---|---|---|
| `guest_mcp_event` | TAINTED_GUEST | TRUSTED_HOST | `GuestMCPController` | `CapabilityBroker` | Yes | Structural metadata filtering |
| `guest_model_relay` | TAINTED_GUEST | EXTERNAL_PROVIDER | `ContainedModelHarness` | `CapabilityBroker` | Yes | Token & size budget enforcement |
| `host_collapse_signal` | TRUSTED_HOST | TAINTED_GUEST | `BurnPurgeEngine` | None (Direct) | Yes | Immediate SIGKILL & cgroup purge |
| `quarantine_replay_read` | QUARANTINE | TRUSTED_HOST | `QuarantinedReplayViewer` | `SealedReplayEngine` | Yes | Authenticated decryption |
