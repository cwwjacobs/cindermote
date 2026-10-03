# Changelog

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Version numbers come from `cindermote/__init__.py`; a `.dev` suffix marks an
unreleased tree.

## [Unreleased] — 1.0.1.dev0

Nothing here has been released or tagged. The merged repairs from
[PR #1](https://github.com/cwwjacobs/cindermote/pull/1) and
[PR #2](https://github.com/cwwjacobs/cindermote/pull/2) (fail-closed observation
handling, snapshot library resolution, the supported-host microVM boot chain) are
also unreleased; see the README's *Repair and evidence*.

### Removed

These modules claimed more than they did, were not called by any entry point, or
both. Nothing in the shipped agent-probe, browser-probe or Incident Gate paths
imported them.

- `sealed_replay.py` and `quarantined_replay_viewer.py`. The "sealed" file was a
  SHA-256 XOR keystream (not AES-GCM as documented) that stored neither its salt
  nor its nonce, so it could not be decrypted, carried an unkeyed hash instead of a
  MAC, and the viewer returned `ACCESS_GRANTED` for a wrong key or a tampered file
  without decrypting anything. Replaced by the HPKE and secretstream evidence path
  that agent-probe already used, plus `scripts/open-agent-probe-evidence.py`.
- `ash_receipt.py` and `schemas/ash-receipt-v1.schema.json`. No entry point used
  it; it signed placeholder hashes (`"pinned-kernel-sha256"`), left its timestamp
  outside the signature, and used PBKDF2 as a MAC. Replaced in the docs by the
  signed envelopes in `agent_probe/receipt.py` and `observer/receipt.py`.
- `burn_purge.py` (untested; reported a network namespace as removed whenever `ip`
  was missing), `contained_model_relay.py` (returned raw model output to its caller,
  defaulted to a specific provider) and `contained_model_harness.py`.
- `dashboard/`: a static mock with hard-coded numbers that answered "ADMIT" to
  any input and offered MCP detonation, which the product does not do.
- `docs/UKSL-review-repair.md`: internal working notes.
- `agent_probe/_hpke_reference.py` and `agent_probe/_secretstream_reference.py`:
  byte-identical copies of `hpke.py` and `secretstream.py` that the "cross-validation"
  tests compared the real modules against.

### Added

- `scripts/open-agent-probe-evidence.py`: the offline viewer for sealed guest
  evidence. It escapes hostile text so terminal control sequences are not
  interpreted.
- `cindermote --version`; one version constant for the CLI and `mote/detonate.py`
  (they previously said v2.0 and v1.1 for a 1.0.0 release).
- `cindermote incident-gate doctor` reports `READY`, `DEGRADED` or
  `FAIL_PREREQUISITES_MISSING`, with per-check `required` flags and a `--strict`
  option that fails a degraded host.
- `cindermote kernel-laws` validates the registries in `docs/` against the tree and
  the kernel laws (it previously validated hard-coded sample data and could not fail).
- `SECURITY.md`, `CONTRIBUTING.md`, this file, and `pyproject.toml` tool
  configuration (ruff, mypy, coverage).
- CI: Python 3.11, 3.12 and 3.13 matrix, a lint-and-types job, a coverage gate, and a
  manual `supported-host.yml` workflow for a self-hosted KVM runner (not yet run).
- Tests: `test_agent_probe_guest.py` (the real in-guest agent against the real host
  control loop and broker, with a scripted provider), `test_crypto_vectors.py`
  (RFC 9180 A.2.1 known-answer vector, PyCA interoperability, secretstream misuse),
  `test_receipt_verification.py`, `test_evidence_viewer.py`, `test_cli.py`.
- A non-vacuous rename audit: code and configuration may not use the predecessor
  name outside the three documents NAMING.md lists.

### Changed

- **Behavior change:** as root, the legacy namespace runner now requires a writable
  cgroup v2 mount and is denied otherwise. Previously a writable tmpfs at
  `/sys/fs/cgroup` (cgroup v1 or hybrid hosts) was accepted and the runner wrote
  limit files that enforced nothing. Unprivileged runs are unchanged.
- **Behavior change:** the legacy runner's job directory is `/tmp/cindermote-<euid>/`
  (owner-only, refused if it is a symlink or owned by someone else) instead of a
  shared `/tmp/cindermote/`.
- `sign_envelope` refuses publicly known placeholder keys on the real receipt path;
  `derive_exit_code` requires the complete witness table for an `ALLOW` exit.
- The egress proxy applies its own public-address tables (IPv6 must be global
  unicast; special-purpose ranges are refused) on top of `ipaddress.is_global`,
  whose tables differ between Python releases (`fec0::1` passed on 3.11 to 3.13,
  `3fff::1` on 3.12.3).
- The egress worker's purge check no longer counts zombie processes as surviving
  group members. On hosts whose PID 1 reaps orphans slowly (or never, as in many
  containers) it previously reported unverified cleanup for a clean run.
- Group/world-writable source files now fail with a message naming the file and the
  fix (`chmod -R go-w`, or `umask 022`).
- The doctrine registries (`docs/FIELD_ATLAS.md`, `SEAM_REGISTRY.md`,
  `CAPABILITY_MANIFEST.md`, `BOUNDARY_LEDGER.md`, `COLLAPSE_CUES.md`) describe the
  components that exist, with a status for each. README status, scope and limits were
  rewritten to match; `docs/legacy-deprecation.md` no longer promises behavior that
  does not exist.
- `cindermote detonate` prints a deprecation notice for the legacy artifact types.
- Generated `policy/golden-snapshot.*` and tool caches are gitignored.

### Fixed

- `verify_envelope`, `derive_exit_code` and the legacy `verify_signature` raised
  `TypeError` or `ValueError` on malformed receipts (non-ASCII, non-string or NaN
  fields) instead of reporting them invalid.
- `incident-gate doctor` said "READY" with no KVM, no cgroups and a not-ready
  Firecracker runtime, and claimed receipts could be unsigned (the observer key is
  created on first use).
- Lint: unused imports and ambiguous names (`ruff check .` is clean).

### Not changed

- Files that are hash-pinned into the guest rootfs were not edited, so the pinned
  rootfs in `policy/firecracker-assets.lock.json` still applies. See
  [CONTRIBUTING.md](CONTRIBUTING.md#hash-pinned-guest-sources-read-before-editing).

## [1.0.0] — 2026-09-23

First public release. Its notes state that the legacy Incident Gate fails where it
runs (eight tests on the release tree) and can record an `ALLOW` when the probe
payload never executed; those defects are repaired on `main` and unreleased.
