# Capability Manifest — Component Permissions

Declared default dispositions. `cindermote kernel-laws` requires every
capability to need a broker, requires unknown capabilities to resolve to
`COLLAPSE`, and requires this table to match the reference decision table in
`capability_brokers.py` exactly.

The shipped agent-probe path does not consult this table. Its fixed allow and
deny sets live in `agent_probe/protocol.py` and are enforced by
`agent_probe/broker.py`.

| Capability | Component | Broker Required | Default Disposition |
|---|---|---|---|
| `mcp_tool_echo` | `GuestMCPController` | Yes | ALLOW |
| `mcp_tool_invocation` | `GuestMCPController` | Yes | ALLOW |
| `model_provider_relay` | `AgentProbeGuestAgent` | Yes | ALLOW |
| `evidence_submission` | `GuestEvidenceSealer` | Yes | ALLOW |
| `synthetic_secret_access` | `GuestMCPController` | Yes | DENY |
| `guest_network` | `GuestMCPController` | Yes | DENY |
| `filesystem_access` | `GuestMCPController` | Yes | DENY |
| `process_spawning` | `GuestMCPController` | Yes | DENY |
| `host_path_access` | `GuestMCPController` | Yes | COLLAPSE |
| `real_secret_request` | `GuestMCPController` | Yes | COLLAPSE |
| `broker_bypass_attempt` | `GuestMCPController` | Yes | COLLAPSE |
| *unknown capability* | *any* | Yes | COLLAPSE |
