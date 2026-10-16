# Cinder Incident Gate Report

## Attack Chain Coverage

Each probe below simulates one step of the July 2026 OpenAI/Hugging Face
attack chain and detonates it through the **real Cindermote S0-S4 sandbox**
(namespace isolation, chroot, seccomp, ptrace, capability drop).

Verdicts come from host-observed evidence, not guest self-reports.

**Overall: CONTAINMENT BREACH DETECTED**

| Probe | Risk | Decision | Isolation | Purge | Held |
|-------|------|----------|-----------|-------|------|
| registry_proxy_abuse | suspicious | EVALUATION_INCOMPLETE | ✅ | ✅ | ❌ |
| lateral_movement | suspicious | EVALUATION_INCOMPLETE | ✅ | ✅ | ❌ |
| metadata_access | suspicious | EVALUATION_INCOMPLETE | ✅ | ✅ | ❌ |
| credential_harvest | suspicious | EVALUATION_INCOMPLETE | ✅ | ✅ | ❌ |
| outbound_exfil | suspicious | EVALUATION_INCOMPLETE | ✅ | ✅ | ❌ |
| tainted_output | suspicious | EVALUATION_INCOMPLETE | ✅ | ✅ | ❌ |

## Detailed Results

### registry_proxy_abuse
**Step 1-2: Agent abuses package proxy to reach external registries**

- Observed risk: `suspicious` (expected: `hostile`)
- Gate decision: `EVALUATION_INCOMPLETE` (expected: `DENY`)
- ⚠️ Observation: `EVALUATION_INCOMPLETE` — no completed payload observation; this is not execution coverage
- Detector rules fired: `['payload_observation_incomplete']`
- ⚠️ Missing expected rules: `['network_exfil_attempt']`
- Namespace isolation: `True`
- Seccomp loaded: `True`
- Purge verified: `True`

### lateral_movement
**Step 3: Privilege escalation and lateral movement to private networks**

- Observed risk: `suspicious` (expected: `hostile`)
- Gate decision: `EVALUATION_INCOMPLETE` (expected: `DENY`)
- ⚠️ Observation: `EVALUATION_INCOMPLETE` — no completed payload observation; this is not execution coverage
- Detector rules fired: `['payload_observation_incomplete']`
- ⚠️ Missing expected rules: `['namespace_escape_attempt', 'network_exfil_attempt']`
- Namespace isolation: `True`
- Seccomp loaded: `True`
- Purge verified: `True`

### metadata_access
**Step 4: Cloud metadata SSRF via 169.254.169.254**

- Observed risk: `suspicious` (expected: `hostile`)
- Gate decision: `EVALUATION_INCOMPLETE` (expected: `DENY`)
- ⚠️ Observation: `EVALUATION_INCOMPLETE` — no completed payload observation; this is not execution coverage
- Detector rules fired: `['payload_observation_incomplete']`
- ⚠️ Missing expected rules: `['network_exfil_attempt']`
- Namespace isolation: `True`
- Seccomp loaded: `True`
- Purge verified: `True`

### credential_harvest
**Step 4-5: Ambient credential harvesting from filesystem and env**

- Observed risk: `suspicious` (expected: `hostile`)
- Gate decision: `EVALUATION_INCOMPLETE` (expected: `DENY`)
- ⚠️ Observation: `EVALUATION_INCOMPLETE` — no completed payload observation; this is not execution coverage
- Detector rules fired: `['payload_observation_incomplete']`
- ⚠️ Missing expected rules: `['cred_harvest_pattern']`
- Namespace isolation: `True`
- Seccomp loaded: `True`
- Purge verified: `True`

### outbound_exfil
**Step 6: Arbitrary outbound data exfiltration**

- Observed risk: `suspicious` (expected: `hostile`)
- Gate decision: `EVALUATION_INCOMPLETE` (expected: `DENY`)
- ⚠️ Observation: `EVALUATION_INCOMPLETE` — no completed payload observation; this is not execution coverage
- Detector rules fired: `['payload_observation_incomplete']`
- ⚠️ Missing expected rules: `['network_exfil_attempt']`
- Namespace isolation: `True`
- Seccomp loaded: `True`
- Purge verified: `True`

### tainted_output
**Step 6: Tainted output with embedded host commands**

- Observed risk: `suspicious` (expected: `hostile`)
- Gate decision: `EVALUATION_INCOMPLETE` (expected: `DENY`)
- ⚠️ Observation: `EVALUATION_INCOMPLETE` — no completed payload observation; this is not execution coverage
- Detector rules fired: `['payload_observation_incomplete']`
- Namespace isolation: `True`
- Seccomp loaded: `True`
- Purge verified: `True`

## Containment Proof

⚠️ Some boundaries did not hold. See details above.
