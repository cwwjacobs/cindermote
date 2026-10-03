# Collapse Cues & Trigger Actions

The doctrine's declared default action for each cue. `cindermote kernel-laws`
requires every action to be one of ALLOW, DENY, QUARANTINE or COLLAPSE and
requires `unknown_capability_request` to be COLLAPSE.

agent-probe does not consult this table. It maps its own outcomes to gate
decisions in `agent_probe/ksl.py`: a hard trip is DENY, capability drift is
RESCOPE_REQUIRED, and telemetry loss is EVALUATION_INCOMPLETE.

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
