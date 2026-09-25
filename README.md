# Cindermote Hotcell — Scalar Kernel Runtime

Release 1.0.0.

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
| Supported-host (bare-metal KVM) end-to-end run | **Not yet demonstrated** | `tests/firecracker/test_supported_host_e2e.py` is opt-in |
| Legacy namespace profile (`mote/detonate.py`) and Cinder Incident Gate | Deprecated (`docs/legacy-deprecation.md`); integration tests currently fail on hosts where they run (see Known issues) | `tests/test_incident_gate.py` |

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

## Known issues

- **Incident Gate results.** The legacy namespace profile builds a golden
  rootfs snapshot from the host on first use (`policy/golden-snapshot.tar.gz`,
  not distributed). On Debian/Ubuntu multiarch layouts the built snapshot
  cannot start its interpreter (the library closure loses SONAME symlinks, so
  e.g. `libexpat.so.1` / `libz.so.1` are not resolvable inside the chroot);
  the shared-library resolution defect itself is still open. On such hosts
  `TestCinderProbeIntegration` now skips with the observation failure class
  reported, keeping "not admitted" separate from execution coverage. On
  GitHub-hosted runners the sandbox admission check fails, so these tests
  skip and CI stays green without exercising them.
- **Incomplete execution evidence.** Fixed: the legacy reducer separates a
  completed payload observation from interpreter-startup,
  snapshot/library-load, admission, and observer failure. Incomplete
  observation now records `payload_observation_incomplete` and maps to
  `EVALUATION_INCOMPLETE` with full uncertainty, a bounded loader diagnostic,
  and a non-success exit; `ALLOW` requires a completed observation
  (`observation.status == COMPLETE` in the signed receipt). Remaining caveat:
  some hostile probes were observed classified `benign` / `ALLOW` on runs
  where the payload did execute, so detector-rule coverage on the deprecated
  profile still needs a supported host to re-verify.
- **File permissions.** Two `tests/firecracker/` tests reject group-writable
  source files. Clone with `umask 022`.

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

`python3 -m unittest discover -s tests` runs only 88 tests: it does not find
`tests/firecracker/` (no `__init__.py`) or pytest-style test functions. Use
pytest for the full suite.

Recorded results for the current baseline are in `VALIDATION.md`.

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
