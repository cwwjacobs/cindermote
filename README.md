# Cindermote Hotcell — Scalar Kernel Runtime

Post-1.0.0 main (`1.0.1.dev0`); no new release has been published. The
[1.0.0 release](https://github.com/cwwjacobs/cindermote/releases/tag/v1.0.0)
predates the fail-closed repairs below and its notes call its legacy gate
unreliable. Use main for the current source; the supported-host result below
is bounded to the audited commit and host, not a new release claim.

Cindermote is a collapse-ready runtime for handling untrusted
agent material inside disposable Firecracker microVMs. Only bounded
classifications, hashes, and authenticated receipts are meant to cross back to
the trusted host.

Policy version: `cindermote-hotcell-v1.3` (`policy/hotcell-policy.json`).

## What it does today

- **agent-probe v0** (Firecracker): gives one passive `skill.md` to a disposable
  LLM inside a microVM. The model is offered declared tools plus decoy
  "prohibited" tools (read a secret, run a shell command, POST to the network,
  install a package, change policy). Only fixed action codes and hashes reach the
  host broker. A prohibited or undeclared proposal hard-trips: egress is revoked,
  the run stops, and the gate decision is `DENY` (`RESCOPE_REQUIRED` for an attempt
  to change policy or widen authority). The raw transcript is sealed to an offline
  key and read with `scripts/open-agent-probe-evidence.py`.
- **browser-probe** (Firecracker): passive Chromium/CDP inspection of one
  authorized URL behind a pinned-DNS CONNECT proxy.
- **Cinder Incident Gate** (legacy namespace sandbox, deprecated): six hostile
  containment probes with signed per-job receipts and a Markdown report. It runs
  without KVM, so it is the quickest way to see the evidence format.

### Scope and limits

- agent-probe handles a single passive `skill.md`. Executable skills, MCP servers
  and code targets are out of scope, and host-native MCP execution is disabled.
- Detection efficacy has not been measured. A run records whether the sacrificial
  model, given this text, tried a prohibited action once. There are no published
  true- or false-positive rates, and a model that resists the injection produces
  no signal. `ALLOW` leaves the artifact on `HOLD`; it is never a safety verdict.
- Receipts are HMAC-SHA256 signed with a host-local key. They prove integrity to
  whoever holds that key, not to a third party.
- A jailed Firecracker agent run completed on the audited Void host with a
  deliberately invalid provider key. Its guest, egress, and cleanup witnesses
  verified, but the gate was `EVALUATION_INCOMPLETE`. A live-provider `ALLOW`
  has never been demonstrated.

## Current status

| Area | Status | Evidence |
|---|---|---|
| Firecracker `agent-probe` v0 (one passive `skill.md` target) and `browser-probe` profiles | Implemented; unit and component tested | `tests/test_agent_probe_*.py`, `tests/firecracker/` |
| In-guest agent decision logic | Implemented; the real guest agent is tested against the real host control loop and broker with a scripted provider | `tests/test_agent_probe_guest.py` |
| Evidence encryption (RFC 9180 HPKE + libsodium secretstream) | Implemented; round-trip, known-answer (RFC 9180 A.2.1) and PyCA interoperability tests | `tests/test_crypto_vectors.py`, `tests/test_agent_probe_crypto.py` |
| Offline evidence viewer for sealed guest evidence | Implemented; unit tested | `tests/test_evidence_viewer.py`, `tests/test_vertical_spine.py` 10 |
| Signed receipts: tamper detection, malformed input reported as invalid, default keys refused | Implemented; unit tested | `tests/test_receipt_verification.py`, `tests/test_agent_probe_runner.py`, `tests/test_vertical_spine.py` 07–09 |
| Capability broker and collapse mesh | Reference models only; **not wired to any entry point** | `tests/test_vertical_spine.py` 06, `tests/test_cindermote_spine.py`, [FIELD_ATLAS](docs/FIELD_ATLAS.md) |
| Declared registries (seams, capabilities, cues, components) | Checked against the tree by `cindermote kernel-laws` | `tests/test_kernel_laws.py` |
| Host-native MCP execution (init, `tools/list`, `tools/call`, vertical run) | **Disabled in this baseline**; calls raise `HostNativeExecutionDisabled` | `tests/test_vertical_spine.py` 01–05 |
| Supported-host KVM agent-probe | On Void `6.18.57_1`, root preflight passed all 24 checks and one jailed run completed with guest, egress, and cleanup witnesses verified. The invalid provider key kept the gate incomplete. | [Validation record](VALIDATION.md), [audit](docs/audits/2026-10-16-security-audit.md), [published evidence](docs/audits/evidence/2026-10-16/README.md) |
| Browser-profile KVM | A controlled HTTPS page loaded in a jailed Firecracker VM with Chromium's sandbox active, all four evidence streams complete, and purge verified. The five-case gate still fails at its clean case: Chromium made five blocked background requests to unauthorized Google origins, so the signed decision is `DENY`, not `ALLOW`. | [Browser follow-up](docs/audits/2026-10-16-browser-followup.md), [proof bundle](docs/audits/evidence/2026-10-16-browser-followup/README.md) |
| Live-provider agent `ALLOW` | **Not demonstrated** | The supported-host run intentionally used an invalid provider key. |
| Legacy namespace profile (`mote/detonate.py`) and Cinder Incident Gate | Deprecated; snapshot startup was repaired and six hostile probes completed with `DENY`, signed receipts, and verified cleanup on the audited host. Incomplete observation fails closed; root runs require real cgroup v2. | [Regression tests](tests/test_incident_gate.py), [audit](docs/audits/2026-10-16-security-audit.md), [deprecation](docs/legacy-deprecation.md) |

## Design invariants

These are the rules the runtime is built toward. The status table above says
which ones are exercised today.

1. **Untrusted material isolation:** raw untrusted semantic material, tool
   descriptions, schemas, prompts, resources, files, and model responses stay
   inside the guest execution path.
2. **Metadata-only host boundaries:** only bounded classifications, hashes,
   structural metadata, policy events, terminal decisions, teardown evidence,
   and authenticated receipts cross to the trusted host.
3. **Deterministic collapse:** unknown capability requests or policy violations
   trigger host-owned Kernel Collapse that does not depend on guest cooperation.
4. **Sealed evidence:** the full guest transcript survives only as ciphertext
   sealed to an offline key, readable through the separate offline viewer.
5. **Missing evidence is failure, not success.**

## Repair and evidence

The [1.0.0 validation](VALIDATION.md#2026-09-23--release-100-tree)
reproduced eight Incident Gate failures: the host-built snapshot interpreter
could not start, yet missing observations could reduce to a clean verdict.
[PR #1](https://github.com/cwwjacobs/cindermote/pull/1) requires explicit
completed observation and telemetry proof, blocks human ALLOW overrides of
incomplete evidence, and persists signed failure receipts after runtime errors.

[PR #2](https://github.com/cwwjacobs/cindermote/pull/2) repairs snapshot SONAME
and stdlib placement, multi-stage hostile-probe detection, and the Firecracker
boot chain. Mount-inspection failures remain not-ready; both RAM mounts must
prove `noswap`. The locally built rootfs is pinned with its build receipt.
The historical supported-host run booted a real microVM and verified cleanup;
a dummy provider key produced `PROVIDER_FAILURE` / `EVALUATION_INCOMPLETE`.
That is execution evidence, not a live-provider ALLOW result.

Later work on the unreleased tree (see [CHANGELOG.md](CHANGELOG.md)) removed
modules that claimed more than they did, made receipt verification total
(malformed receipts are invalid, never an exception), required a real cgroup v2
mount before the legacy runner reports cgroup limits, and made the doctrine
registries and `kernel-laws` check real rather than self-fulfilling.

The [2026-10-16 audit](docs/audits/2026-10-16-security-audit.md) fixed a
Void snapshot loader failure, bounded archive links, corrected containment
failure labels, repaired job-image formatting permissions and the isolated
egress worker's interpreter selection, and updated the browser gate to read
current v2 evidence. CI now pins official Actions and direct tooling, avoids
persisting checkout credentials, and adds Dependabot and CodeQL workflows.
The [published evidence bundle](docs/audits/evidence/2026-10-16/README.md)
contains signed agent receipts and road traces for two failures and the
completed run, browser smoke evidence, legacy verifier outputs, and the full
portable test summary. The encrypted guest evidence and the host-specific
archive remain local; public HMAC receipts cannot be independently
authenticated without the host's private observer key.

The [browser follow-up](docs/audits/2026-10-16-browser-followup.md) retained
four successive signed failure receipts, including one bound to the exact
source commit. The final run demonstrates real
navigation and complete browser, CDP, egress, and VM observation, but the
controlled-fixture gate remains `FAIL`: blocked Chromium startup requests
produce an honest `DENY`. The [follow-up proof bundle](docs/audits/evidence/2026-10-16-browser-followup/README.md)
includes the receipts, evidence, gate results, build receipt, and hashes.

Follow the [regression tests](tests/test_incident_gate.py),
[runner failure tests](tests/test_agent_probe_runner.py),
[mount-proof tests](tests/firecracker/test_firecracker_runtime.py),
[CI workflow](.github/workflows/ci.yml), and [validation record](VALIDATION.md).
Hosted CI checks portable behavior and the root job-image contract; it does
not establish supported-host KVM execution. The host run covered audited code
at local commit `0526265`; the published branch carries the same runtime code
with later documentation and evidence additions. A new release needs its own
claim boundary.

## Known issues and remaining limitations

- **Supported-host proof is bounded.** Root preflight and jailed execution
  passed on one Void host for local audit commit `0526265`. The public bundle
  contains receipts and hashes, while the private HMAC key and encrypted guest
  evidence stay on that host. A later main commit or release is not itself a
  fresh supported-host run.
- **Browser-profile gate is failing.** The clean controlled-fixture case loaded
  in Firecracker with complete observation and verified cleanup, but Chromium
  attempted five unauthorized background requests. The proxy blocked them and
  the signed gate decision was `DENY`; the remaining four fixture cases were
  not run by that gate. This is not a five-case pass.
- **Live-provider ALLOW is unverified.** No live credential was used in the
  recorded supported-host run. A successful ALLOW outcome is not guaranteed
  by supplying a credential; it must be executed and verified.
- **Host admission is conditional.** GitHub-hosted runners skip legacy
  integration tests when sandbox admission fails. Such skips are not
  execution coverage. The legacy profile remains deprecated, and host-native
  MCP execution remains disabled.
- **The legacy runner needs a real cgroup v2 hierarchy as root.** On cgroup v1 or
  hybrid hosts a root run is denied rather than pretending to apply limits;
  unprivileged runs use the explicit `degraded-user` mode. `cindermote
  incident-gate doctor` reports `READY`, `DEGRADED` or `FAIL_PREREQUISITES_MISSING`.
- **Guest agent limits.** A provider response over 64 KiB cannot be sealed as one
  evidence record, so the guest fails (`GUEST_FAILURE`, reported as an
  infrastructure failure, never an `ALLOW`). Fixing it changes a hash-pinned guest
  source and needs a rootfs rebuild and re-pin ([CONTRIBUTING.md](CONTRIBUTING.md)).
- **Host and file permissions matter.** Clone with `umask 022` (Debian and Ubuntu
  default to 002) or run `chmod -R go-w .`; trusted source gates reject
  group-writable files and say which file. The dedicated egress worker selects
  a trusted system Python when available; a fallback interpreter still needs
  a traversable standard-library path. Follow [RUNBOOK.md](RUNBOOK.md) for
  pinned assets, RAM mounts, service identities, and host preparation.

## Main commands

Requirements: Linux, Python 3.11, 3.12 or 3.13 (all three run in CI), system
`libsodium`, and the pinned `requirements/ci-test.txt` dependencies. Linting
uses the pinned `requirements/ci-lint.txt` dependencies.

```bash
# Verify import compilation
python3 -m compileall -q .

# Full portable test suite with the coverage gate (CI also repeats the image contract as root)
python3 -m pytest -q tests --cov --cov-report=term-missing:skip-covered

# Lint, types, and the doctrine registry check
ruff check .
python3 cli.py kernel-laws

# Vertical spine checks
python3 tests/test_vertical_spine.py

# See what an evidence run looks like (no KVM needed; unprivileged is fine)
./bin/cindermote incident-gate doctor
./bin/cindermote incident-gate run

# Recheck the manifest hashes, receipt schemas, and all HMAC signatures
./scripts/verify-incident-gate-evidence.py \
  --expect-all receipts/incident-gate/<run-id>

# Package a source release
./scripts/package-release.sh
```

### Starting and viewing runs

There is currently a command-line interface and retained receipts, but no
browser dashboard, account-based run list, or button to create a run. Each
invocation below starts a fresh job with its own ID. Firecracker jobs require
the [prepared host](RUNBOOK.md) and root privileges.

```bash
# Start a new passive browser run and print its signed receipt.
sudo ./.venv/bin/python -B mote/detonate.py --browser-url https://example.org/

# Inspect a browser run by the job ID in that receipt.
job_id=mf-web-REPLACE_WITH_ID
sudo ./.venv/bin/python -B -m json.tool "receipts/${job_id}.json"
sudo ./.venv/bin/python -B -m json.tool "receipts/${job_id}.browser-evidence.json"

# Or create an unprivileged legacy demonstration run with a Markdown report.
./bin/cindermote incident-gate run
```

Browser receipts live in `receipts/mf-web-*.json`; their evidence sidecars have
the same job ID. Check `gate.final_decision`, `browser_probe.findings`,
`telemetry_incomplete`, and `purge.verified_externally` together. A completed
command does not by itself mean `ALLOW`. Legacy Incident Gate reports live in
`receipts/incident-gate/run-*/`; agent-probe's receipt and road files live in
`receipts/agent-probe/` as described in its [runbook](docs/agent-probe/RUNBOOK.md).
These folders are local and intentionally ignored by Git; the audit bundles
publish selected copies only.

`python3 -m unittest discover -s tests` does not find
`tests/firecracker/` (no `__init__.py`) or pytest-style test functions. Use
pytest for the full suite.

Recorded results and the commits they cover are in [VALIDATION.md](VALIDATION.md).

## Documentation

- `PROVENANCE.md` — Lineage and frozen upstream attribution.
- `MIGRATION_FROM_MOTEFIELD.md` — Active surface rename record.
- `NAMING.md` — Product and codebase naming rules.
- `VALIDATION.md` — Recorded verification runs and status.
- `docs/audits/2026-10-16-security-audit.md` — Latest defensive audit,
  remediations, retained failures, and exact Firecracker proof boundaries.
- `docs/audits/2026-10-16-browser-followup.md` — Controlled-fixture browser
  follow-up, remaining failed gate, and reproduced image hashes.
- `docs/audits/evidence/2026-10-16/README.md` — Public proof bundle,
  checksums, and limits of third-party verification.
- `CHANGELOG.md` — What changed, including removals and behavior changes.
- `CONTRIBUTING.md` — Setup, checks, and the hash-pinned guest sources.
- `SECURITY.md` — Reporting a vulnerability and what is in scope.
- `docs/ULTRA_GOAL.md` — Ultra Goal specification (target design).
- `docs/FIELD_ATLAS.md` — Trust field component map and what exists.
- `docs/CAPABILITY_MANIFEST.md` — Declared capability registry.
- `docs/SEAM_REGISTRY.md` — Guest-host boundary path registry.
- `docs/BOUNDARY_LEDGER.md` — Boundary ledgers and dispositions.
- `docs/COLLAPSE_CUES.md` — Deterministic triggers and actions.
- `docs/UNRESOLVED_RISKS.md` — Recorded limitations and open risks.

## License and Origin

Licensed under the **Apache License 2.0**. See `LICENSE`.

Created by Corey Jacobs ([`cwwjacobs`](https://github.com/cwwjacobs)).
See `NOTICE`.
