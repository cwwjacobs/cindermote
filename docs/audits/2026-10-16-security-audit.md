# Defensive security audit — 2026-10-16

## Scope and claim boundary

This audit started from a fresh clone of `cwwjacobs/cindermote` at
`2a2a2671008512e1ecd77ba0af2c207a27a280dd`. It covered the Python runtime,
legacy namespace containment, Firecracker admission path, signed evidence,
dependency and CI supply chain, repository security settings, and the test
claims in the documentation.

The completed hostile-probe result in this audit is the explicit
`degraded-user` legacy profile. The Firecracker assets and host devices were
verified, and a networkless raw microVM smoke boot reached the pinned guest
init. Later root preflight passed. After two recorded infrastructure failures,
one jailed agent-probe run completed with signed guest, egress, and cleanup
witnesses; its deliberately invalid provider key left the gate incomplete.
A public-site browser smoke booted and cleaned up but returned a fail-closed
`DENY` with incomplete telemetry. The controlled-fixture browser gate and a
live-provider `ALLOW` remain unproven. Severity below is audit triage, not a
CVSS score.

## Finding ledger

| ID | Severity | Status | Finding and disposition |
|---|---|---|---|
| CM-2026-01 | High | Fixed and demonstrated | Snapshot creation flattened merged-`/usr` library aliases. On this Void host, the loader started but could not find `libpthread.so.0`; six probes failed before payload execution. Snapshot creation now reconstructs only aliases whose resolved targets stay within known library roots. A rebuilt snapshot ran all six probes to complete `DENY` decisions. |
| CM-2026-02 | Medium | Fixed and tested | The Incident Gate rendered any failed containment predicate as “CONTAINMENT BREACH DETECTED,” including infrastructure failure with isolation and purge intact. It now reports one of `ALL_BOUNDARIES_HELD`, `BOUNDARY_FAILURE_DETECTED`, `EVALUATION_INCOMPLETE`, or `CONTAINMENT_TEST_FAILED`. |
| CM-2026-03 | Medium | Fixed and tested | The Python compatibility fallback for snapshot extraction called `extractall` after checking member paths and special files, but did not explicitly bound symbolic- and hard-link targets. Both link kinds are now rejected when their resolved target escapes the extraction root. |
| CM-2026-04 | Medium | Fixed in tree | CI used mutable GitHub Action tags and unpinned Python install commands, and checkout credentials remained in Git configuration while repository code ran (including one root test). Official actions are pinned to immutable commits, checkout persistence is disabled, direct CI dependencies are pinned and wheel-only, and weekly Dependabot plus pinned CodeQL workflows were added. Transitive Python dependencies are still resolver-selected rather than hash-locked. |
| CM-2026-05 | Low | Fixed and tested | Three proxy startup invariants used `assert`, which Python optimization can remove. They now raise explicit configuration or startup errors. |
| CM-2026-06 | Audit quality | Fixed | Coverage source discovery included `.venv`, producing a misleading 3.74% result in this workspace. `.venv` is now omitted. The first corrected audit run measured 68.24%; the final expanded tree measures 67.32%, above the 60% gate. |
| CM-2026-07 | Operational | Host admission and jailed runtime proven; verdicts limited | The initial unprivileged preflight exited 2. After reboot and root host preparation, Corey supplied a root preflight with all 24 required checks true and `ready=true`. Two root agent-probe attempts failed with signed incomplete receipts. A third completed in Firecracker, persisted sealed evidence, and proved all three witnesses and cleanup; the intentionally invalid provider key produced `PROVIDER_FAILURE` and `EVALUATION_INCOMPLETE`, so no `ALLOW` is claimed. The public-site browser smoke booted and cleaned up but returned `DENY` with incomplete telemetry. |
| CM-2026-08 | Repository | Partly addressed in tree | GitHub secret scanning and push protection are enabled and there were no open secret alerts. Main has no branch protection; repository-wide Action SHA enforcement is off; Dependabot alerts/security updates are disabled; no CodeQL analysis exists yet. The workflows in this tree take effect only after publication. |
| CM-2026-09 | High scanner label | Reviewed, accepted | Bandit reports SHA-1 in `guest/browser_agent.py`. RFC 6455 requires SHA-1 for the `Sec-WebSocket-Accept` handshake value; this use does not authenticate content or protect secrets. The hash-pinned guest source was left unchanged and the finding remains visible. |
| CM-2026-10 | Operational | Fixed and tested | The job image was created mode `0444` before `mkfs.ext4` wrote its filesystem, so an unprivileged formatter failed with `Permission denied while setting up superblock`. The image is now mode `0600` during formatting and `0444` afterward; the previously failing image test passes. This was reproduced in a local non-root test, not established as the cause of the root Firecracker run failure. |
| CM-2026-11 | High | Fixed and exercised on host | On Void, the isolated egress worker inherited a Python under the operator's mode-0700 home. After dropping to `cindermote-proxy`, a lazy standard-library import failed (`unknown encoding: ascii`, then `No module named 'queue'` in a staged diagnostic). The worker now prefers a root-owned, non-writable `/usr/bin/python3` that meets Python 3.11+, while preserving the prior interpreter fallback. An isolated root worker start and a jailed agent-probe run both completed, and teardown was verified. |
| CM-2026-12 | Audit quality | Fixed and tested | The supported-host browser gate imported the v1 guest evidence validator, but current host receipts use v2 evidence. It now imports the v2 validator/reducer and has a regression check for that schema. The controlled-fixture gate itself was not run because no public controlled HTTPS fixture was supplied. |

Bandit's other medium findings were manually traced: the two `exec` calls run
source that is read once, permission checked or taken from the admitted probe
set, hashed, and compiled from those same bytes; the browser worker loads its
trusted sources only after privilege drop. Fixed `/tmp` strings identify paths
whose creation and ownership checks are implemented elsewhere. These findings
remain in the retained scanner output rather than being globally suppressed.

## Retained proof, including failure

The selected public receipts, road traces, browser evidence, verifier output,
console results, and checksums are in the
[2026-10-16 evidence bundle](evidence/2026-10-16/README.md). It includes both
failed and completed runs. The bundle does not include the host's HMAC key or
encrypted guest evidence; see its README for the verification boundary.

The host-specific machine-readable material is under
`.cindermote/audit/2026-10-16/` and is intentionally ignored by Git. It contains:

- `pytest-baseline.xml` and `coverage-baseline.json`;
- `pytest-final.xml` and `coverage-final.json`;
- `bandit.json`, `bandit-final.json`, and `pip-audit-final.json`;
- `firecracker-preflight.json`, `firecracker-smoke-config.json`, and the full
  `firecracker-smoke.log` serial transcript;
- `github-security-snapshot.json`;
- `incident-gate-failure-verification.json` and
  `incident-gate-success-verification.json`.
- `evidence-manifest.json`, which records path, byte length, and SHA-256 for 47
  audit, snapshot, and Incident Gate files. Its own SHA-256 is
  `09b325a8a82ce24599e95bba90be92cdc0079764fc96e0bf9c38a928cb37e503`.
- `host-package-checkpoint.txt`, `host-root-preflight-user-supplied.md`, and
  `unprivileged-preflight-after-host-setup.json` preserve the later host
  preparation result and the expected non-root failure separately. These
  follow-up files postdate the 47-file manifest. The separate
  `evidence-manifest-followup.json` hashes these files, the focused test
  output, and the generated quarantine public key.
- `root-supported-host-failure-pasted.txt`,
  `agent-probe-supported-host-console-first-failure.txt`,
  `root-agent-smoke-failure.md`, and copied receipt/road JSON files preserve
  the first privileged agent-probe failure and its claim boundary.
- `agent-probe-supported-host-console-rerun.txt` preserves the second failure
  with a signed `proxy_setup` / `BrowserEgressWorkerProtocolError` trace.
- `agent-probe-supported-host-console-third-run.txt`, copied signed roads,
  `job-605f1a346b11ec76.guest-evidence.json.enc`, and
  `supported-host-verification.json` preserve the completed jailed runtime.
- `browser-public-smoke-console.txt` and copied `mf-web-2af9af0e` receipt and
  evidence preserve the public-site browser `DENY` without promoting it to a
  controlled-fixture pass.
- `evidence-manifest-root-failure.json` and `evidence-manifest-final.json`
  hash the later failure, success, browser, test, coverage, and audit records.

The append-only run trees are:

- failed honestly: `receipts/incident-gate/run-20261016T065642Z-344a69dd`;
- successful legacy containment:
  `receipts/incident-gate/run-20261016T070335Z-7351c694`.

Both trees contain a master JSON file, Markdown report, and six child receipts.
The verifier authenticated all twelve child HMACs and checked every child hash,
schema, and job identity. The successful run's manifest and report SHA-256
values are, respectively:

```text
895003da7cf4a60bfe23f94225fecf577d7b5115f7a849c155c0295d94f51111
a17abcae0242cec5a562b67b0b24ed1308d9680848278479ddfb4b3093cb84c8
```

These HMAC receipts are locally tamper-evident to a holder of `.observer_key`;
they are not a third-party attestation. The key was never printed or copied
into the audit documents.

## Firecracker evidence and remaining work

The KingFast migration backup supplied Firecracker v1.16.1, jailer v1.16.1,
vmlinux-6.1.155, and the browser rootfs. Fresh preflight matched the lock file:

| Asset | SHA-256 |
|---|---|
| Firecracker | `2fd0171309af7e24cf8dafc8a6f921c1434c49b5f9349bb996b7ed0a4deb8aa7` |
| jailer | `1f3a0c1fe86212d0001819bfe0819071c01208b3ccc9398c3b3bc1b84cf21edd` |
| guest kernel | `e20e46d0c36c55c0d1014eb20576171b3f3d922260d9f792017aeff53af3d4f2` |
| browser rootfs | `5a12eb095f39bcb58179a5729edec70c1e2244470256eb7c38ed42f09c8fa881` |
| rootfs receipt | `ce4bb74387bed504210e671c2fec62f1072b3ec005883908c6822c33f7ef1ddb` |

`/dev/kvm` and `/dev/net/tun` are both read/write for the current user, and the
required `ip`, `nft`, `mkfs.ext4`, `python3`, and `sysctl` commands exist. A
networkless direct run of Firecracker v1.16.1 started one vCPU under KVM,
mounted the pinned rootfs read-only, and ran `/sbin/cindermote-init`. Because
the smoke configuration intentionally omitted the TAP interface and job drive,
init failed at the missing `eth0` and the guest panicked; Firecracker then
stopped cleanly with exit 0. The config and log SHA-256 values are:

```text
c2f9f4c206a67f42d201dc18105007792bb731ff14ece939dd89b9d01bea43b6  firecracker-smoke-config.json
356bfd9e96257edf2a38a9b2275d18b93f6220872ad034f3bf29eeeaaf03e707  firecracker-smoke.log
```

Corey rebooted into `6.18.57_1`, disabled swap, and ran the host preparation
script in a normal terminal. The supplied root preflight reports `ready=true`
with all 24 required checks passing, including dedicated identities,
owner-only RAM mounts, cgroup v2, KVM, TUN, and pinned assets. The direct
operator-account check sees the new kernel, disabled swap, and the `noswap`
runtime mount. It correctly reports `ready=false` without root, because it
cannot inspect the shadow database, owner-only jailer mount, or delegated
cgroup. Corey then ran the jailed agent-probe test with `sudo`. Its signed
receipt was created, but the test failed in 5.28 seconds at
`execution_status=INFRASTRUCTURE_FAILED`; no encrypted guest evidence file was
created. Corey copied the root-owned receipt and road files into the audit
folder. Independent verification passed both envelope signatures and all three
receipt-to-road hashes. The signed receipt says cleanup was verified; its
guest and egress witnesses are false. The road trace records
`UNEXPECTED_RUNTIME_FAILURE` without a stage or exception class. The cause of
that run therefore remains unknown. A later local non-root test found and
fixed a separate job-image formatting mode defect; it cannot explain a root
run by itself.

The second privileged attempt, `job-efad177c49dc0b70`, failed at
`proxy_setup` with `BrowserEgressWorkerProtocolError`. Its receipt and road
files also passed signature and hash verification. An isolated root worker
probe returned the bounded `sandbox_failed` code. A staged diagnostic showed
that the worker's inherited Python could not load standard-library modules
from beneath the operator's private home after dropping privileges. After the
worker began using the compatible root-owned system Python, an isolated worker
started and verified its purge.

The third privileged agent-probe attempt, `job-605f1a346b11ec76`, passed its
supported-host test in 6.85 seconds. Its signed receipt reports
`execution_status=COMPLETE`, `cleanup_status=VERIFIED`, and all guest, egress,
and cleanup witnesses true. The encrypted evidence file SHA-256 is
`a58a6c4e0afb0546e46fdc6aed075b68a39cd584ae63d322926a4fc22df455cf`;
the receipt SHA-256 is
`35e3ad0d64900be78b3a6bf4208ff547886f183f84f7503ecb65ff4fe7835cc1`.
Independent verification passed the receipt and frozen-road signatures, all
three receipt-to-road hashes, and the evidence root/job binding. Root cleanup
inspection found no owned stale job tokens, named network namespaces, or
Firecracker/jailer/worker processes. The deliberately invalid provider key
yielded guest `PROVIDER_FAILURE`, `task_complete=false`, and
`gate_decision=EVALUATION_INCOMPLETE`; this is a runtime completion proof, not
a successful model task verdict.

A separate passive browser smoke against `https://example.com/` admitted a
jailed VM and verified purge, then returned signed `DENY` with incomplete
telemetry. The evidence contains five blocked Google-origin background
requests and an egress telemetry-loss event. The receipt signature, evidence
hash, and v2 reduction were independently rechecked. The controlled-fixture
browser gate was not run; it requires two public HTTPS origins under our
control and a private fixture token. During this verification, its stale v1
evidence imports were found and fixed in tree.

## Verification summary

- Pre-host full suite: 451 passed, 3 skipped, 1 deselected; 191 subtests passed;
  68.24% coverage. Final full suite after the worker and gate fixes: 456
  passed, 3 skipped, 191 subtests passed; 67.32% coverage.
- Direct vertical spine: 15/15 passed against the host, including KVM presence.
- Static checks: compile, ruff, typed core, and kernel-laws passed.
- Verifier negative control: appending one byte to a copied child receipt made
  verification exit 1 with a manifest-hash mismatch; the other 5 children
  remained independently valid.
- Installed dependency audit: 46 distributions, zero known vulnerabilities in
  the advisory database used by `pip-audit` 2.10.1.
- Firecracker: raw networkless KVM boot reached the pinned guest init; root
  host admission passed after reboot. The third privileged agent-probe run
  completed in the jail with all three witnesses and sealed evidence. Its
  invalid provider key kept the gate incomplete. The browser public-site
  smoke booted and purged but failed closed; the controlled-fixture browser
  gate and live-provider `ALLOW` remain unproven.
