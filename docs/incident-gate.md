# Cinder Incident Gate

## Purpose

The Cinder Incident Gate tests whether Cindermote interrupts the consequence
paths associated with the July 2026 OpenAI/Hugging Face incident. It does not
recreate an undisclosed exploit and does not claim universal sandbox security.

Each probe is detonated through the existing Cindermote S0-S4 path:

1. snapshot verification
2. artifact preflight and detector analysis
3. namespace, chroot, capability, ptrace, seccomp, and optional cgroup setup
4. untrusted probe execution
5. host-side evidence reduction and policy judgment
6. externally verified purge
7. signed per-job receipt

The Incident Gate has one canonical implementation: `incident_gate.py`, loaded
as `cindermote.incident_gate` through the repository's package bridge.

## Probes

| Probe | Consequence tested |
|---|---|
| `registry_proxy_abuse` | direct package-registry and DNS/TCP access |
| `lateral_movement` | RFC1918 reachability, namespace escape, privileged-file access |
| `metadata_access` | cloud metadata and link-local access |
| `credential_harvest` | ambient environment and filesystem credentials |
| `outbound_exfil` | arbitrary TCP, UDP, and DNS exfiltration |
| `tainted_output` | hostile output and host-command injection patterns |

A probe passes only when all of the following are true:

- observed risk is at least the declared expected risk
- the policy decision exactly matches the expected decision
- every expected detector rule fired
- namespace isolation and seccomp are confirmed by host evidence
- purge is externally verified

A `suspicious` result does not satisfy a probe expecting `hostile`.

## Evidence retention

Every command run receives a unique append-only evidence tree:

```text
receipts/incident-gate/run-<UTC timestamp>-<random id>/
├── alerts/
├── quarantine/
├── receipts/                 # signed per-job Cindermote receipts
├── cinder-incident-gate.json # master summary with child receipt hashes
└── cinder-incident-gate-report.md
```

The gate never deletes the repository's existing `receipts/`, `quarantine/`, or
`alerts/` directories. Library calls without an explicit evidence path use a
temporary per-run tree, which keeps tests hermetic and prevents ownership from a
prior privileged run from contaminating later tests.

## Running

Doctor check:

```bash
./bin/cindermote incident-gate doctor
```

Run all probes:

```bash
./bin/cindermote incident-gate run
```

Run one probe:

```bash
./bin/cindermote incident-gate run --case outbound_exfil
```

Choose a base directory for append-only run evidence:

```bash
./bin/cindermote incident-gate run --receipt-dir /var/lib/cindermote/incident-gate
```

The command prints the exact run directory. It returns zero only when every
selected boundary satisfies its complete evidence contract.

## Isolation claim

For Python-script probes, the current detonation path uses Cindermote's Linux
namespace sandbox. In non-root mode, cgroups and mlock are unavailable, and the
receipt reports that degraded mode explicitly. Firecracker availability is
reported by `doctor`, but these Python-script probes do not by themselves prove
a Firecracker microVM path.

The browser-probe subsystem has a separate Firecracker runtime and supported-host
gate. Do not describe a namespace-only Incident Gate run as Firecracker proof.

## Tests

Unit and hermetic contract tests:

```bash
python -m pytest tests/test_incident_gate.py -k 'not TestCinderProbeIntegration' -q
```

Real sandbox integration tests:

```bash
python -m pytest tests/test_incident_gate.py -k TestCinderProbeIntegration -v
```

Full repository suite:

```bash
python -m pytest -q
```

## Non-claims

Passing the gate does not prove immunity to unknown hypervisor or kernel
vulnerabilities, CPU side channels, physical host failure, or consequence paths
not represented by the probes. It proves only that the tested Cindermote controls
produced the declared host-observed evidence for that run.
