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

## 2026-10-03 — unreleased tree after the Week 1–3 hardening (branch `claude/pensive-ramanujan-2wsvyu`)

Base commit `ed82ef5` plus the commits on this branch. The counts below were recorded
on the working tree immediately before it was committed. No Firecracker or KVM
execution was possible, so this entry validates portable behavior only.

### Environment

| Item | Value |
|---|---|
| Host | Firecracker-VM container, Linux 6.18.44, x86_64; **no `/dev/kvm`** |
| cgroups | v1/hybrid: `/sys/fs/cgroup` is a **tmpfs**, cgroup2 is mounted at `/sys/fs/cgroup/unified` |
| PID 1 | reaps orphaned zombies only after about 1.9 s |
| Python | 3.11.15 (system), 3.12.3 and 3.13.14 (virtualenvs); `cryptography` 49.0.0 / 50.0.2, `pytest` 9.1.1 |
| Checkout | copy of the working tree, `chmod -R go-w`, `umask 022`; non-root user for the unprivileged runs |

### Starting point, measured in the same environment

| Run | Result |
|---|---|
| Documented pytest command as root, commit `ed82ef5` | 247 passed, **2 failed**, 23 skipped, 1 deselected, 129 subtests passed (35 s) |
| Same, non-root, clean permissions | 266 passed, **1 failed**, 5 skipped, 1 deselected, 129 subtests passed (146 s) |

The failures were `test_surviving_group_descendant_is_killed_and_invalidates_telemetry`
(zombie reaping latency against a 0.5 s recheck, both runs) and, as root only,
`test_privileged_benign_traces_validated_child_inside_exact_cgroup` (the legacy runner
accepted the tmpfs at `/sys/fs/cgroup` as a cgroup hierarchy). Both are fixed.

### Results on this tree

| # | Command | Result |
|---|---|---|
| 1 | `python3 -m compileall -q .` | exit 0 |
| 2 | `python3 tests/test_vertical_spine.py` | 15 run, 14 passed, 1 skipped (no `/dev/kvm`) |
| 3 | `ruff check .` | all checks passed |
| 4 | `mypy` on the 16 files listed in `ci.yml` | no issues |
| 5 | `python3 cli.py kernel-laws` | PASS (6 seams, 12 capabilities, 8 cues, 15 components) |
| 6 | non-root, Python 3.11.15: `python3 -m pytest -q tests --deselect=…job_image… --cov` | **446 passed, 4 skipped, 1 deselected**, 189 subtests passed (139 s); coverage 68.1% |
| 7 | same, Python 3.12.3 | **446 passed, 4 skipped, 1 deselected**, 189 subtests passed (106 s); coverage 68.2% |
| 8 | same, Python 3.13.14 | **446 passed, 4 skipped, 1 deselected**, 189 subtests passed (136 s); coverage 68.1% |
| 9 | CI worst case (sandbox integration classes deselected), 3.11 / 3.12 / 3.13 | 428 passed, 4 skipped, 19 deselected each (7 s); coverage 64.75% / 64.73% / 64.76% against `fail_under = 60` |
| 10 | root, Python 3.11.15, same command with `--cov` | **427 passed, 23 skipped, 1 deselected**, 189 subtests passed (33 s); coverage 65.3% |

Coverage counts every module under the repository, including ones no test imports
(`guest/agent_probe_agent.py` was invisible to the earlier 66.6% figure and is now
counted). The 4 skips in runs 6–8 are the opt-in browser KVM gate, the supported-host
agent-probe test, the privileged cgroup test (now skipped on a host without a real
cgroup v2 mount instead of failing), and `/dev/kvm` in the vertical spine. In run 10 the
18 sandbox-admission skips are the same as at the starting point: a root run on this host
cannot be admitted because it has no real cgroup v2 mount.

### Hosted CI on the pushed branch

Exact head `073ee292c4e9985ee4491e23e7c371f9a6c54ec1`,
[CI run 37094478277](https://github.com/cwwjacobs/cindermote/actions/runs/37094478277):
`Lint and types` passed (ruff, mypy, `kernel-laws`), and the unprivileged suite plus the
root job-image contract passed on all three interpreters:

| Job | Unprivileged suite | Coverage (gate 60%) | Root job-image contract |
|---|---|---|---|
| Python 3.11.16 | 429 passed, 21 skipped, 1 deselected, 189 subtests passed (49 s) | 66.84% | 1 passed |
| Python 3.12.14 | 429 passed, 21 skipped, 1 deselected, 189 subtests passed (66 s) | 66.83% | 1 passed |
| Python 3.13.15 | 429 passed, 21 skipped, 1 deselected, 189 subtests passed (60 s) | 66.82% | 1 passed |

The hosted runner skips the sandbox integration tests, so it reports 21 skips against 4 on
the unprivileged host above. Hosted CI does not establish KVM execution.

### Mutation check of the new guest-agent tests

Seven deliberate faults were applied one at a time to a scratch copy of
`guest/agent_probe_agent.py` (trip mapped to `DENIED`, soft findings not counted,
undeclared tool names passed to the host verbatim, token overrun ignored, incomplete token
reporting ignored, provider failure treated as complete, target hash check skipped).
`tests/test_agent_probe_guest.py` failed for all seven; the first run missed the
undeclared-tool-name fault, and `test_model_chosen_tool_names_never_reach_the_host_verbatim`
was added to catch it.

### Not run

- Any Firecracker/KVM execution, the browser-profile gate, and a live-provider `ALLOW`.
- The root job-image contract test (`mkfs.ext4`); CI runs it with root.
- The manual `supported-host.yml` workflow: it was parsed as YAML but never executed (it
  needs a self-hosted KVM runner). The `ci.yml` changes did run on hosted runners (above).
- The hash-pinned guest sources were not edited, so the pinned rootfs is unaffected;
  supported-host admission was not re-run to confirm that.

## 2026-10-16 — local defensive audit and Void host repair

Fresh clone of `cwwjacobs/cindermote` at base commit
`2a2a2671008512e1ecd77ba0af2c207a27a280dd`; the audited changes are the tree
containing this entry. Environment: Void Linux, kernel `6.18.56_1` x86_64,
CPython 3.13.16 in `.venv`, non-root user. The physical KingFast drive was
mounted at `/run/media/operator/Storage`; its migration backup contained the
exact Firecracker cache whose four asset hashes match
`policy/firecracker-assets.lock.json`.

### Preserved failure and repair proof

The first real Incident Gate run is retained at
`receipts/incident-gate/run-20261016T065642Z-344a69dd`. All six signed child
receipts are structurally and cryptographically valid, but every result is
`EVALUATION_INCOMPLETE`: the chrooted interpreter could not find
`libpthread.so.0`. Isolation and purge were still recorded true. This was not
counted as containment success.

Snapshot construction was repaired to preserve safe host library aliases such
as `/usr/lib64 -> lib`. The rebuilt local snapshot has SHA-256
`bcc366cc562dd54d2433e9f8e77923bb80c53e37f3c2bc1ec96ec99e4e536e2a`.
The next run is retained at
`receipts/incident-gate/run-20261016T070335Z-7351c694`: all six hostile probes
completed, were classified hostile, received `DENY`, met their detector-rule
expectations, confirmed isolation, and verified purge.

`scripts/verify-incident-gate-evidence.py` independently re-read the success
run against `policy/hotcell-policy.json` and the local observer key. It verified
all 6/6 child schemas, HMAC signatures, manifest hashes, and job identities.
The success manifest hash is
`895003da7cf4a60bfe23f94225fecf577d7b5115f7a849c155c0295d94f51111`;
the Markdown report hash is
`a17abcae0242cec5a562b67b0b24ed1308d9680848278479ddfb4b3093cb84c8`.
The verifier also authenticated all 6/6 receipts in the failed run, preserving
that failure with the same standard of evidence.

### Final local checks

| Command or check | Result |
|---|---|
| `python -m compileall` over project sources | exit 0 |
| `ruff check .` | all checks passed |
| `mypy` on the CI typed core plus the new verifier | no issues |
| `python cli.py kernel-laws` | PASS: 6 seams, 12 capabilities, 8 cues, 15 components |
| `python tests/test_vertical_spine.py` against the real host | 15/15 passed, including `/dev/kvm` presence |
| full documented pytest command with coverage | **451 passed, 3 skipped, 1 deselected; 191 subtests passed** in 111.42 s; 68.24% coverage |
| targeted snapshot/fail-closed integration after repair | 9 passed, 49 deselected |
| `pip-audit --local` | 46 installed distributions checked; no known vulnerabilities found |
| Bandit over production Python sources | 36 findings: 1 high, 7 medium, 28 low; high finding reviewed as the RFC 6455-mandated SHA-1 WebSocket accept calculation, not a security digest |

The pre-repair full-suite baseline was **432 passed, 18 skipped, 1 deselected;
189 subtests passed**, with 67.07% project coverage after correcting the
virtual-environment omission. The repair converted the 15 locally runnable
sandbox skips to execution and added four regression tests.

### Firecracker claim boundary

The cached `firecracker` and `jailer` binaries both identify as v1.16.1. Fresh
preflight verifies the pinned Firecracker, jailer, vmlinux-6.1.155, and browser
rootfs hashes, plus read/write access to `/dev/kvm` and `/dev/net/tun`.

A separate networkless, non-jailer smoke run used the exact pinned kernel and
read-only rootfs. Firecracker reported a successful microVM start; guest serial
output identified KVM, mounted the ext4 root read-only, and executed
`/sbin/cindermote-init`. The init then failed as expected because this bounded
smoke configuration deliberately supplied neither `eth0` nor the `/dev/vdb`
job drive; the guest panicked and Firecracker shut down cleanly with exit 0.
The serial log SHA-256 is
`356bfd9e96257edf2a38a9b2275d18b93f6220872ad034f3bf29eeeaaf03e707`.

At this pre-host checkpoint, the production Cindermote Firecracker profile was
**not ready**: this
managed environment is read-only and `nosuid`, has a zero capability bounding
set, the dedicated service identities and RAM runtime have not been created,
one swap device is active, the cgroup mount is read-only, and tmpfs `noswap`
has not been proven. No jailer, TAP network, job-drive, browser, or agent-probe
end-to-end success is claimed. The root-required job-image contract was also
not run locally.

The detailed finding ledger and evidence inventory are in
`docs/audits/2026-10-16-security-audit.md`. Machine-readable evidence is kept
under `.cindermote/audit/2026-10-16/`; it is intentionally gitignored because
it contains host-specific reports. The two append-only Incident Gate run trees
are likewise gitignored.

## 2026-10-16 — host admission follow-up

Corey rebooted into `6.18.57_1`, disabled the unused 15 GiB swapfile, and ran
`scripts/prepare-firecracker-host.sh` in a normal root terminal. The supplied
`mote/detonate.py --firecracker-preflight` result for the browser profile has
`ready=true` and all 24 required checks passing. It verifies pinned assets,
dedicated locked VMM/proxy identities, `/dev/kvm`, `/dev/net/tun`, root-owned
RAM mounts with `noswap`, disabled host swap, delegated cgroup v2, and required
host commands. A separate direct operator-account check confirms the new
kernel, no active swap, and the `noswap` runtime mount; it exits 2 for
root-only checks as designed.

This superseded the earlier host-admission limitation above. At this point,
jailed Firecracker execution, TAP networking, the read-only job drive, sealed
agent evidence, and purge still required validation. The later follow-up below
records the live runs. The machine-specific checkpoint is retained in
`.cindermote/audit/2026-10-16/host-root-preflight-user-supplied.md`.

The first privileged agent-probe run then failed: `1 failed in 5.28s`. It
created a signed receipt for `job-4d8fcdd89ab3ce1a`, but the receipt payload
reported `execution_status=INFRASTRUCTURE_FAILED`; no encrypted guest evidence
file appeared. The test stopped before asserting cleanup. Corey copied the
root-owned receipt and road files into `.cindermote/audit/2026-10-16/`.
Independent verification found both envelope signatures valid and all three
receipt-to-road hashes matching. The signed receipt says cleanup was verified,
while guest and egress witnesses were false. The road trace gives only
`UNEXPECTED_RUNTIME_FAILURE`, so the failed stage is still unknown. The full
console output and a bounded failure account remain in the audit directory.

After this failure, a local non-root test exposed a separate job-image defect:
the image was mode `0444` before `mkfs.ext4` wrote it. Formatting now uses
mode `0600`, then switches to `0444`; the affected test and six other focused
tests pass, with the supported-host test skipped without root. The next
privileged attempt was configured to print only a bounded failure stage,
exception class, and numeric errno if it failed again.

## 2026-10-16 — jailed runtime and browser smoke follow-up

The second root agent-probe test failed in 5.26 seconds. Its bounded signed
road for `job-efad177c49dc0b70` records `proxy_setup` and
`BrowserEgressWorkerProtocolError`; the receipt reports infrastructure
failure. Both signatures and all three receipt-to-road hashes verify. An
isolated root worker test returned the static `sandbox_failed` response.
Staged diagnostics showed that the worker's Python was under the operator's
mode-0700 home, where its dedicated UID could not lazily import the standard
library after dropping privileges. The worker now selects a root-owned,
non-writable `/usr/bin/python3` if it supports Python 3.11 or newer; the
isolated worker then started and verified purge.

The third root agent-probe test passed: `1 passed in 6.85s`. The synthetic
target and intentionally invalid provider key produced `job-605f1a346b11ec76`
with `execution_status=COMPLETE`, all guest/egress/cleanup witnesses true,
`cleanup_status=VERIFIED`, and a sealed evidence file. The receipt SHA-256 is
`35e3ad0d64900be78b3a6bf4208ff547886f183f84f7503ecb65ff4fe7835cc1`;
the encrypted evidence SHA-256 is
`a58a6c4e0afb0546e46fdc6aed075b68a39cd584ae63d322926a4fc22df455cf`.
The copied receipt and frozen-road signatures, all road hashes, and the
evidence job/root binding verify independently. Root inspection found no
stale owned job tokens, named network namespace, or Firecracker/jailer/worker
process. The guest status is `PROVIDER_FAILURE`, task incomplete, and gate
`EVALUATION_INCOMPLETE` because the provider key was deliberately invalid;
this does not establish a model-task `ALLOW` verdict.

A separate root browser probe of public `https://example.com/` admitted a
Firecracker VM and verified teardown, but its signed receipt returned `DENY`:
five unauthorized Google-origin background requests were blocked and an
egress telemetry-loss event made the trace incomplete. The receipt signature,
evidence hash, and v2 reduction verify. This is a fail-closed smoke result,
not a pass of the controlled-fixture browser gate. During verification, the
gate's stale v1 evidence imports were corrected to use the current host v2
validator and reducer; a regression test now covers the version.

The machine-specific console outputs, copied signed receipts, encrypted
evidence, and file hashes are under `.cindermote/audit/2026-10-16/`.
`supported-host-verification.json` records the independent checks. The
controlled-fixture browser gate and a live-provider agent `ALLOW` remain
unverified.

Final unprivileged suite after these repairs:

```text
python -m pytest -q tests --cov=. --cov-report=json:.cindermote/audit/2026-10-16/coverage-after-supported-host.json
456 passed, 3 skipped, 191 subtests passed in 107.49s
Total coverage: 67.32% (required: 60%)
```

Repository-wide Ruff, the 17-file typed core, Kernel Laws, Python compilation,
and `git diff --check` also passed. The job-image contract now runs
unprivileged, so CI no longer deselects it; CI still repeats that contract as
root. The exact suite and coverage output is retained in
`.cindermote/audit/2026-10-16/`.

## 2026-10-16 — controlled HTTPS browser follow-up

The host remained on Void `6.18.57_1` with swap disabled. The root browser
preflight passed all 24 required checks before each controlled-fixture gate
attempt. Two temporary public HTTPS origins served a locally controlled
fixture, and the gate checked that both returned the expected source hash.
The fixture token, observer HMAC key, and raw Chromium diagnostic log stayed
local.

Three retained signed failure attempts show progress without a fabricated
pass. Candidate 2 failed guest navigation with the bounded code
`navigation_err_network_changed`. Candidate 3 loaded the page inside a jailed
Firecracker VM with Chromium's sandbox active, but one allowed fixture proxy
tunnel remained incomplete when the proxy stopped. Candidate 4 added a bounded
teardown drain: the browser, CDP, egress, and VM streams were all complete;
rootfs read-only, guest tmpfs writes, and externally verified purge were
recorded. Five background Chromium requests to unauthorized Google origins
were blocked. The signed receipt is therefore `DENY`, and the clean-case gate
result is `FAIL`. The remaining four fixture cases were not run.

The candidate-4 rootfs and build receipt hashes are
`a83985565010ce930f10241bac06c0e550ca9b13b3a59dd9f52ef93214d19b7c`
and `75e713f326a1384efd29ab4bb5f3cdf0d63261f2cb3420eaed688e37541c234b`.
A second build from the same pinned inputs and local Docker cache reproduced
both hashes. Local verification checked all three gate/receipt HMACs, schemas,
evidence-file SHA-256 bindings, and reductions. The public bundle carries
selected byte-for-byte copies and its own SHA-256 index; the observer key is
not published, so external authentication is not claimed.

Final portable suite after these guest and receipt changes:

```text
PYTHONDONTWRITEBYTECODE=1 ./.venv/bin/python -B -m pytest -p no:cacheprovider -q tests
461 passed, 3 skipped, 196 subtests passed in 105.96s
```

Ruff, `dash -n guest/cindermote-init`, `python3 cli.py kernel-laws`, and
`git diff --check` passed. The detailed result and remaining Chromium startup
blocker are in [the browser audit](docs/audits/2026-10-16-browser-followup.md)
and [public proof bundle](docs/audits/evidence/2026-10-16-browser-followup/README.md).
