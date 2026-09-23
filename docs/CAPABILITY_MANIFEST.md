# Capability Manifest — Component Permissions

| Capability | Component | Broker Required | Default Disposition |
|---|---|---|---|
| `mcp_tool_echo` | `GuestMCPController` | Yes | ALLOW |
| `mcp_tool_invocation` | `GuestMCPController` | Yes | ALLOW |
| `model_provider_relay` | `ContainedModelHarness` | Yes | ALLOW |
| `evidence_submission` | `AshReceipt` | Yes | ALLOW |
| `synthetic_secret_access` | `GuestMCPController` | Yes | DENY |
| `guest_network` | `GuestMCPController` | Yes | DENY |
| `filesystem_access` | `GuestMCPController` | Yes | DENY |
| `process_spawning` | `GuestMCPController` | Yes | DENY |
| `host_path_access` | `GuestMCPController` | Yes | COLLAPSE |
| `real_secret_request` | `GuestMCPController` | Yes | COLLAPSE |
| `broker_bypass_attempt` | `GuestMCPController` | Yes | COLLAPSE |
| *unknown capability* | *any* | Yes | COLLAPSE |
