# Collapse Cues & Trigger Actions

| Trigger Condition | Cue ID | Required Action |
|---|---|---|
| Request for host path (e.g. `/etc/shadow`) | `host_path_access` | COLLAPSE |
| Request for real secret or API key | `real_secret_request` | COLLAPSE |
| Request for undeclared capability | `unknown_capability_request` | COLLAPSE |
| Request for undeclared network egress | `undeclared_destination` | COLLAPSE |
| Attempted bypass of capability broker | `broker_bypass_attempt` | COLLAPSE |
| Malformed JSON-RPC frame or size limit breach | `malformed_broker_frame` | COLLAPSE |
| Loss of guest telemetry or watchdog ping | `telemetry_loss` | COLLAPSE |
| Raw model response relay attempt to host | `raw_output_relay_attempt` | COLLAPSE |
