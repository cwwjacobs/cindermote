# Field Atlas — Cindermote Component Map

| Component | Trust Zone | Description |
|---|---|---|
| `GuestMCPController` | TAINTED_GUEST | Executes inside guest; manages stdio/JSON-RPC MCP target. |
| `ContainedModelHarness` | TAINTED_GUEST | Runs inside guest execution path; inspects raw MCP content. |
| `CapabilityBroker` | BROKERED_SEAM | Validates requested capabilities and maps dispositions. |
| `CollapseMesh` | BROKERED_SEAM | Evaluates deterministic triggers for kernel collapse. |
| `BurnPurgeEngine` | TRUSTED_HOST | Host-owned process teardown and external cleanup verification. |
| `SealedReplayEngine` | TRUSTED_HOST | Encrypts raw replay data locally with per-run random key. |
| `QuarantinedReplayViewer` | QUARANTINE | Separate viewer path for inspecting sealed replay ciphertext. |
| `AshReceipt` | TRUSTED_HOST | Authenticated metadata-only evidence receipt emitted after run. |
