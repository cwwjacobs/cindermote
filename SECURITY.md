# Security Policy

## Supported versions

Only the current `main` branch is supported. There are no maintenance branches.
The [1.0.0 release](https://github.com/cwwjacobs/cindermote/releases/tag/v1.0.0)
predates fail-closed repairs that exist only on `main`; do not deploy it.

## Reporting a vulnerability

Please do not open a public issue for a vulnerability.

Use GitHub private vulnerability reporting: open the repository's **Security**
tab, choose **Advisories**, then **Report a vulnerability**. Include the commit,
the host (kernel, KVM or not, root or not), the exact commands, and the receipt or
log output that shows the problem. Do not include live credentials.

This is a single-maintainer project. Reports are acknowledged as soon as
practical, and no response-time commitment is made.

## What is in scope

Reports about behavior the documentation claims, for example:

- a guest reaching the host other than through the declared seams
  ([SEAM_REGISTRY](docs/SEAM_REGISTRY.md)), or raw guest text appearing in a
  host-visible receipt, event, log or exit path;
- a receipt that verifies when it should not, or a verifier that raises instead of
  reporting an invalid receipt;
- a bypass of the egress proxy: DNS pinning, peer pinning, the public-address
  policy, or its byte, connection and time budgets;
- a flaw in privilege separation, teardown or purge verification that leaves guest
  processes, cgroups, network devices or RAM-jail files behind while reporting
  success;
- weaknesses in the evidence encryption (HPKE key wrap, secretstream framing) or in
  key and credential handling.

## What is out of scope

- The deprecated legacy namespace profile shares the host kernel by design and is
  documented as weaker than the Firecracker profiles
  ([legacy-deprecation](docs/legacy-deprecation.md)). Bugs in it are welcome;
  "a namespace sandbox is not a VM" is not a finding.
- An attacker with root on the host, or physical access to host memory.
- Behavior of third-party model providers, including what they retain.
- Targets other than a passive `skill.md` (executable code and MCP servers are not
  supported).
- Findings already listed in
  [UNRESOLVED_RISKS](docs/UNRESOLVED_RISKS.md) or
  [agent-probe SECURITY_NOTES](docs/agent-probe/SECURITY_NOTES.md).

## Known limits worth reading first

Receipts are HMAC-signed with a host-local key, so they are not verifiable by third
parties. Detection efficacy has not been measured. A real-hardware run with a live
provider has not been demonstrated. See the README's *Scope and limits* and
*Known issues* sections.
