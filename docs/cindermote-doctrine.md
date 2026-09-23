# Cindermote Doctrine

## Ultra Goal

Cindermote is a collapse-ready, burn-at-any-time Scalar Kernel runtime for ingesting untrusted data and detonating untrusted MCP systems.

The contained model may inspect raw tools, prompts, resources, files, images, schemas, outputs, and latent instructions.

The trusted host agent does **not** ingest raw semantic output.

Every reachable guest-to-host seam is:

- declared,
- brokered or absent,
- instrumented,
- assigned deterministic collapse behavior,
- and represented in authenticated evidence.

A full replay is preserved as sealed evidence without becoming trusted-agent context.

## Vocabulary

| Term | Definition |
|------|-----------|
| **Scalar Kernel** | The Firecracker microVM runtime containing the untrusted guest |
| **Hotcell** | The canonical Cindermote Scalar Kernel image |
| **Collapse** | Deterministic termination of the Scalar Kernel triggered by a violation |
| **Cinder** | Operator-requested termination when no automatic Collapse occurred |
| **Burn** | The teardown mechanism used after Collapse or Cinder |
| **Ash** | The minimal surviving trusted evidence after Burn |
| **Ash Receipt** | The authenticated evidence bundle produced after Burn |
| **Seam** | Any path crossing a trust boundary |
| **Broker** | A host-owned capability gate between guest and host |
| **Collapse Mesh** | The complete set of deterministic collapse cues |
| **Field Atlas** | What exists inside and outside the trust field |
| **Capability Manifest** | What each component may do |
| **Seam Registry** | Every known path crossing trust boundaries |
| **Boundary Ledger** | What is trusted, untrusted, brokered, sealed, or prohibited |
| **Claim Matrix** | What Cindermote can and cannot honestly claim |

## Kernel Laws

1. Raw untrusted semantic output never enters the trusted host agent.
2. Every external capability is brokered, blocked, or absent.
3. Unknown capability requests collapse the kernel.
4. Operator and host-owned policy can initiate Burn at any time.
5. Collapse does not depend on guest cooperation.
6. Burn must produce purge evidence.
7. Replay remains sealed outside a quarantined viewer.
8. Missing evidence is failure, not success.
9. API-provider exposure is an explicit trust boundary.
10. Closure applies only to the declared reachable surface, never to the universe in general.

## Product dispositions

```
ADMIT
ADMIT_WITH_RESTRICTIONS
QUARANTINE
REJECT
INCONCLUSIVE
INFRASTRUCTURE_FAILED
```

## Collapse cues

Each cue maps to `ALLOW`, `DENY`, `QUARANTINE`, or `COLLAPSE`. No ambiguous default.

Examples:

```
undeclared destination
undeclared tool
host-path request
real-secret request
privilege escalation
broker bypass attempt
evidence tampering
policy mutation
unexpected child process
unexpected listening socket
raw-output relay attempt
cross-tenant identifier
unknown protocol frame
telemetry loss
watchdog loss
```