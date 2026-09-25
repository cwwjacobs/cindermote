# Cindermote Hotcell — Scalar Kernel Runtime

Post-1.0.0 main; no new release has been published.

Cindermote is a collapse-ready runtime for handling untrusted
agent material inside disposable Firecracker microVMs. Only bounded
classifications, hashes, and authenticated receipts are meant to cross back to
the trusted host.

Policy version: `cindermote-hotcell-v1.3` (`policy/hotcell-policy.json`).

## Current status

| Area | Status | Evidence |
|---|---|---|
| Firecracker `agent-probe` v0 (one passive `skill.md` target) and `browser-probe` profiles | Implemented; unit and component tested | `tests/test_agent_probe_*.py`, `tests/firecracker/` |
| Evidence encryption (RFC 9180 HPKE + libsodium secretstream) | Implemented; unit tested | `tests/test_agent_probe_crypto.py`, `tests/test_crypto_compat.py` |
| Authenticated Ash Receipts, tamper detection, rejected default keys | Implemented; unit tested | `tests/test_vertical_spine.py` 07–09 |
| Sealed replay with a separate quarantined viewer | Implemented; unit tested | `tests/test_vertical_spine.py` 10 |
| Capability broker: unknown capability resolves to `COLLAPSE` | Decision logic implemented; unit tested | `tests/test_vertical_spine.py` 06 |
| Host-native MCP execution (init, `tools/list`, `tools/call`, vertical run) | **Disabled in this baseline**; calls raise `HostNativeExecutionDisabled` | `tests/test_vertical_spine.py` 01–05 |
| Supported-host KVM agent-probe | Real Firecracker execution demonstrated on the pre-merge branch; final-main revalidation pending | [Validation record](VALIDATION.md); `tests/test_agent_probe_supported_host.py` |
| Browser-profile KVM / live-provider ALLOW | **Not demonstrated** | Opt-in browser gate and live-provider tests remain unrun |
| Legacy namespace profile (`mote/detonate.py`) and Cinder Incident Gate | Deprecated; snapshot startup and hostile-probe classification repaired; incomplete observation fails closed | [Regression tests](tests/test_incident_gate.py), [validation](VALIDATION.md), [deprecation](docs/legacy-deprecation.md) |

## Design invariants

These are the rules the runtime is built toward. The status table above says
which ones are exercised today.

1. **Untrusted material isolation:** raw untrusted semantic material, tool
   descriptions, schemas, prompts, resources, files, and model responses stay
   inside the guest execution path.
2. **Metadata-only host boundaries:** only bounded classifications, hashes,
   structural metadata, policy events, terminal decisions, teardown evidence,
   and authenticated Ash Receipts cross to the trusted host.
3. **Deterministic collapse:** unknown capability requests or policy violations
   trigger host-owned Kernel Collapse that does not depend on guest cooperation.
4. **Sealed replay:** full replays survive only as encrypted local ciphertext,
   readable through a separate quarantined viewer.
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

Follow the [regression tests](tests/test_incident_gate.py),
[runner failure tests](tests/test_agent_probe_runner.py),
[mount-proof tests](tests/firecracker/test_firecracker_runtime.py),
[CI workflow](.github/workflows/ci.yml), and [validation record](VALIDATION.md).
Hosted CI checks portable behavior and the root job-image contract; it does
not establish supported-host KVM execution. The validation record distinguishes
historical branch receipts from evidence for the final merged commit.

## Known issues and remaining limitations

- **Final-main supported-host validation is pending.** The recorded branch
  microVM runs do not prove the shipped HEAD. Root authentication is required
  to rerun the agent-probe check and verify its signed receipts on this host.
- **Browser-profile KVM E2E is unverified.** It needs an operator-controlled
  public HTTPS fixture with a DNS-named certificate.
- **Live-provider ALLOW is unverified.** No live credential was used in the
  recorded supported-host run. A successful ALLOW outcome is not guaranteed
  by supplying a credential; it must be executed and verified.
- **Host admission is conditional.** GitHub-hosted runners skip legacy
  integration tests when sandbox admission fails. Such skips are not
  execution coverage. The legacy profile remains deprecated, and host-native
  MCP execution remains disabled.
- **Host and file permissions matter.** Clone with `umask 022`; trusted source
  gates reject group-writable files. The dedicated egress worker must be able
  to traverse the Python stdlib path. Follow [RUNBOOK.md](RUNBOOK.md) for
  pinned assets, RAM mounts, service identities, and host preparation.

## Main commands

Requirements: Linux, Python 3.11 or newer, system `libsodium`, and
`pip install pytest cryptography`.

```bash
# Verify import compilation
python3 -m compileall -q .

# Full portable test suite (what CI runs, minus one root-only test)
python3 -m pytest -q tests \
  --deselect=tests/test_agent_probe_runtime_protocol.py::test_job_image_copies_opaque_target_without_parsing

# Vertical spine checks
python3 tests/test_vertical_spine.py

# Package a source release
./scripts/package-release.sh
```

`python3 -m unittest discover -s tests` does not find
`tests/firecracker/` (no `__init__.py`) or pytest-style test functions. Use
pytest for the full suite.

Recorded results and the commits they cover are in [VALIDATION.md](VALIDATION.md).

## Documentation

- `PROVENANCE.md` — Lineage and frozen upstream attribution.
- `MIGRATION_FROM_MOTEFIELD.md` — Active surface rename record.
- `NAMING.md` — Product and codebase naming rules.
- `VALIDATION.md` — Recorded verification runs and status.
- `docs/ULTRA_GOAL.md` — Ultra Goal specification (target design).
- `docs/FIELD_ATLAS.md` — Trust field component map.
- `docs/CAPABILITY_MANIFEST.md` — Declared capability registry.
- `docs/SEAM_REGISTRY.md` — Guest-host boundary path registry.
- `docs/BOUNDARY_LEDGER.md` — Boundary ledgers and dispositions.
- `docs/COLLAPSE_CUES.md` — Deterministic triggers and actions.
- `docs/UNRESOLVED_RISKS.md` — Recorded limitations and open risks.

## License and Origin

Licensed under the **Apache License 2.0**. See `LICENSE`.

Created by Corey Jacobs ([`cwwjacobs`](https://github.com/cwwjacobs)).
See `NOTICE`.
