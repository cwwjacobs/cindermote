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
on this Debian multiarch host, so no payload executes (historical failure,
repaired by PRs #1 and #2). The 4 skips are the same as below.

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

## 2026-09-25 — supported-host run (uksl/ksl-08-supported-host)

First run with a genuinely starting snapshot interpreter and a real
Firecracker/KVM microVM execution. Branch `uksl/ksl-08-supported-host` on top
of `uksl/ksl-01-fail-closed`.

### Environment

| Item | Value |
|---|---|
| OS / kernel | Ubuntu 22.04, Linux 6.8.0-138-generic (x86_64), AMD Ryzen 5 5500 |
| Python | 3.12.14 (`.tools/python`), `cryptography` 50.0.1, `pytest` 9.1.1 |
| Firecracker | v1.16.1 + jailer (pinned via `scripts/fetch-firecracker.sh`, sha256 verified), guest kernel vmlinux-6.1.155 |
| Host prep | `/dev/kvm` rw; `scripts/prepare-firecracker-host.sh` as root (swap off, service identities, RAM runtime); docker.io 29.1.3 + buildx 0.30.1 for the pinned rootfs build |
| Checkout | branch checkout with `umask 022` |

### Results

| # | Command | Result |
|---|---|---|
| 1 | `python3 -m compileall -q .` | exit 0 |
| 2 | `python3 tests/test_vertical_spine.py` | 14 run, 14 passed |
| 3 | `python3 -m pytest -q tests --deselect=tests/test_agent_probe_runtime_protocol.py::test_job_image_copies_opaque_target_without_parsing` | **264 passed, 4 skipped, 1 deselected**, 116 subtests passed (105 s) |
| 4 | `python3 -m pytest -q tests/test_incident_gate.py` | **49 passed** (all 13 `TestCinderProbeIntegration` tests execute against a genuinely starting interpreter; 0 skipped) |
| 5 | `sudo env CINDERMOTE_AGENT_PROBE_E2E=1 CINDERMOTE_AGENT_PROBE_E2E_ENDPOINT=... CINDERMOTE_AGENT_PROBE_E2E_MODEL=... CINDERMOTE_AGENT_PROBE_E2E_KEY=... python3 -m pytest -q tests/test_agent_probe_supported_host.py` | **6/6 consecutive passes** (~7 s each) |

Run 3's 4 skips: the opt-in browser KVM gate (needs an operator-run public
HTTPS fixture), the supported-host agent-probe test (skips unprivileged —
preflight correctly reports not-ready without root), the live model-relay
test (needs a local provider key), and one root + writable-cgroup test.

Run 5 evidence (job `job-89bf8f05aace1115`): real microVM boot (jailer +
Firecracker v1.16.1 + vmlinux-6.1.155 + pinned rootfs), guest agent executed,
egress through the privilege-separated CONNECT worker to the pinned provider
origin, and teardown verified. The signed receipt
(`receipts/agent-probe/job-89bf8f05aace1115.receipt.json`, envelope verified
with the observer key) records `execution_status=COMPLETE`,
`cleanup_status=VERIFIED`, all three witnesses complete,
`runtime_failure_code=NONE`, and sealed guest evidence at
`quarantine/agent-probe/`. The model leg used a dummy key against
`https://api.openai.com/v1/chat/completions`, so the guest honestly reports
`PROVIDER_FAILURE` (HTTP 401) and the gate is `EVALUATION_INCOMPLETE` —
incomplete evidence is not promoted to a verdict. A live-provider ALLOW result
remains unverified; a credential alone is not proof that the remaining leg
succeeds.

### Defects fixed to reach this run

- Snapshot library closure dropped SONAME names (multiarch `libexpat.so.1`
  load failure) and placed the stdlib where the chrooted interpreter does not
  look for it; both placements fixed, bounded loader diagnostics retained.
- Rootfs build lost every executable bit (e2fsdroid writes 0644 for all
  regular files): guest init/shell/interpreter were non-executable. The
  toolchain now restores exec bits inode-by-inode and asserts the critical
  set; the asset lock is repinned to the verified build.
- Guest init aborted on kernels that pre-mount devtmpfs; now tolerated.
- Agent-probe vsock connect aborted on the normal boot-time refusal instead
  of retrying; now retries until the deadline.
- Egress proxy could not rebind after TIME_WAIT, failing most back-to-back
  runs; `SO_REUSEADDR` set (active-listener exclusivity unchanged).
- Preflight crashed with `PermissionError` for unprivileged callers on a
  root-owned runtime root; now reports not-ready.
- Legacy probes died at their first blocked socket, so later-stage hostile
  behavior was invisible; socket creation now fails with EPERM under
  observation (namespace-class syscalls still kill), and the `__exec__`
  tainted-output tripwire is detected. `lateral_movement` and
  `tainted_output` are now DENY/hostile on completed observations.
- Preflight's host-kernel check now verifies the operative tmpfs `noswap`
  capability from the real mounts instead of pinning a version string (this
  host: 6.8.0, outside the documented 6.18.x target family).

### Not run

- Browser-profile KVM gate (`tests/firecracker/e2e_supported_host.py`):
  needs an operator-controlled, publicly reachable HTTPS fixture with a
  DNS-named certificate; no such fixture is available on this host.
- A full ALLOW-grade agent-probe run: needs a live provider credential.
- The root-required job-image contract test outside CI.

## Historical branch status

- Portable components: implemented and unit/component tested.
- Legacy namespace profile and Incident Gate: passing on this host with a
  genuinely starting interpreter; fail-closed on incomplete observation.
- Supported-host (KVM) agent-probe end-to-end: passing on this host
  (execution COMPLETE; gate honestly EVALUATION_INCOMPLETE without a live
  provider credential).

## 2026-09-25 — rebased PR #2 integration validation

Exact head: `667a6c82be7aca602a07081964a7dcea8d48bac1`, rebased onto
PR #1 merge `31901805167549f62a66da004c0ac234456cd952`. Its tracked tree
matches original PR #2 head `5892433e35dbdb3b0dfb492d961a0e8ffb606dea`;
merge-commit mount-proof repairs and their regressions were retained.

Environment: Ubuntu 22.04, Linux 6.8.0-138-generic, Python 3.12.14 at
`/home/orz/Downloads/readmeFIXES/.tools/python/bin/python3`, non-root,
`umask 022`. Existing generated snapshot and pinned microVM assets retained.
Initial runs rejected group-writable source metadata. Tracked file permissions
were corrected to the documented requirement, without changing the gate.

| Command | Result |
|---|---|
| `python3 -m compileall -q .` | exit 0 |
| `python3 tests/test_vertical_spine.py` | 14 passed |
| `python3 -m pytest -q -rs tests --deselect=tests/test_agent_probe_runtime_protocol.py::test_job_image_copies_opaque_target_without_parsing` | **268 passed, 4 skipped, 1 deselected; 129 subtests passed** (101.98 s) |
| `python3 -m pytest -q tests/firecracker` | **112 passed, 1 skipped; 113 subtests passed** |

The full-suite skips are browser KVM (no public HTTPS fixture), agent-probe
supported-host (root/explicit environment unavailable), live model relay (no
provider key), and the root/writable-cgroup test. The Incident Gate integration
class executes on this host. The separate job-image contract was attempted
unprivileged and failed at `mkfs.ext4`; CI runs it with root. This local failure
is not counted as a pass or hidden by another test exclusion.

Fresh exact-head CI: [push run](https://github.com/cwwjacobs/cindermote/actions/runs/36127800067)
and [PR run](https://github.com/cwwjacobs/cindermote/actions/runs/36127805996).
Both runs passed on the exact rebased head, including compilation, the
unprivileged suite, and the root job-image contract. Hosted CI does not establish real KVM execution.

## Final-main release gate

PR #2 merged as `e73398292e528410b394d6082a1b4ace8ba02511` after both
exact-head CI runs passed. This documentation correction follows that merge.

The entries above are historical source-tree or branch observations, not
validation of the final shipped HEAD. The post-1.0.0 release remains blocked
until the supported-host command is rerun on final main and its signed receipt,
execution status, cleanup status, witnesses, and gate decision are checked.
Root authentication is currently unavailable in this validation session.
No browser-profile E2E or live-provider ALLOW result is claimed.
