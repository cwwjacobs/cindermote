# Cindermote Validation Record

Each entry records one run: the commit, the environment, the exact commands,
and the counts they produced. Counts are copied from command output, not
estimated.

## 2026-09-23 — release 1.0.0 tree

This is the public 1.0.0 source tree. Unlike the earlier private baseline
below, it does not ship `policy/golden-snapshot.tar.gz`, so the legacy
Incident Gate builds a snapshot from the host on first use. Environment as
below (Debian 13, Python 3.13.5, `umask 022`).

| # | Command | Result |
|---|---|---|
| 1 | `python3 -m compileall -q .` | exit 0 |
| 2 | `python3 tests/test_vertical_spine.py` | 14 run, 14 passed |
| 3 | `python3 -m pytest -q tests --deselect=tests/test_agent_probe_runtime_protocol.py::test_job_image_copies_opaque_target_without_parsing` | **235 passed, 8 failed, 4 skipped, 1 deselected**, 113 subtests passed (37 s) |

All 8 failures are `tests/test_incident_gate.py::TestCinderProbeIntegration`
probe and full-run tests. The host-built snapshot cannot start its interpreter
on this Debian multiarch host, so no payload executes (see `README.md` Known
issues). The 4 skips are the same as below.

## 2026-09-23 — earlier private baseline (with committed snapshot)

This run used the pre-release private source tree, which still contained a
committed golden snapshot built on another host.

### Environment

| Item | Value |
|---|---|
| OS / kernel | Debian 13, Linux 6.12.94 (x86_64) |
| Python | 3.13.5 (venv), `cryptography` 50.0.1, `pytest` 9.1.1 |
| System libraries | `libsodium.so.23` |
| Host features | `/dev/kvm` present; unprivileged user namespaces enabled; Yama `ptrace_scope=1`; not root |
| Checkout | fresh clone with `umask 022` |

### Results

| # | Command | Result |
|---|---|---|
| 1 | `python3 -m compileall -q .` | exit 0 |
| 2 | `python3 tests/test_vertical_spine.py` | 14 run, 14 passed |
| 3 | `python3 -m pytest -q tests --deselect=tests/test_agent_probe_runtime_protocol.py::test_job_image_copies_opaque_target_without_parsing` | **238 passed, 5 failed, 4 skipped, 1 deselected**, 113 subtests passed (65 s) |
| 4 | `python3 -m unittest discover -s tests -p 'test_*.py'` | 88 run, 5 failures, 2 skipped (does not discover `tests/firecracker/` or pytest-style tests) |
| 5 | GitHub Actions `CI` on the private baseline (ubuntu-latest, Python 3.11) | unprivileged job: 230 passed, 17 skipped, 1 deselected; root-required job: 1 passed |

The 5 failures in runs 3 and 4 are all in
`tests/test_incident_gate.py::TestCinderProbeIntegration`:
`test_registry_proxy_abuse_blocked`, `test_lateral_movement_blocked`,
`test_tainted_output_blocked`, `test_full_run_all_contained`, and
`test_full_run_produces_master_receipt`. In the generated report, isolation and
purge held for every probe, but `registry_proxy_abuse` and `tainted_output`
were classified `benign` / `ALLOW`, and `lateral_movement` did not fire the
expected `namespace_escape_attempt` rule.

The 4 skips in run 3 are the opt-in supported-host KVM E2E test, the
supported-host agent-probe test (needs KVM assets and a live provider
credential), the live model-relay test (needs a local provider key), and one
test that needs root and writable cgroup v2.

GitHub-hosted runners skip 13 more tests than run 3, because the Incident Gate
integration class skips itself when its sandbox admission check fails. A green
CI run therefore does not exercise the legacy sandbox.

### What the vertical spine checks

`tests/test_vertical_spine.py` verifies that host-native MCP initialization,
`tools/list`, `tools/call`, protocol initialization, and vertical execution are
**disabled** (tests 01–05); that an unknown capability resolves to `COLLAPSE`
(06); that default signing keys are rejected, unverified cleanup is not
reported as done, and receipt mutation is detected (07–09); that sealed replay
round-trips through the quarantined viewer (10); that `.gitignore` covers keys
and evidence paths (11); that the provenance documents mention Motefield (12);
that the tree compiles (13); and whether `/dev/kvm` exists (14).

### Not run

- Supported-host Firecracker/KVM end-to-end (needs root host preparation with
  `scripts/prepare-firecracker-host.sh`, pinned assets, and credentials).
- The root-required job-image contract test outside CI.

## Status

- Portable components: implemented and unit/component tested.
- Legacy namespace profile and Incident Gate: failing on hosts where they run;
  see `README.md` Known issues.
- Supported-host (KVM) end-to-end: pending.
