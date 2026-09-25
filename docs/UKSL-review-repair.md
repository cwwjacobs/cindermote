# U-KSL review repair — 2026-09-25

Source: https://terminusprotocol.io, core canon v0.5. Operator authorized map,
build, audit and push each passing KSL. No merge authorization is assumed.

## Ultra Stage 1 — map
Goal: repair the reviewed PR batch and publish verified branch updates for CI.
Kernel: preserve Kimi's changes, fail closed on absent proof, retain truthful
coverage claims and historical evidence; no force pushes or unrelated redesign.
Intra: Cindermote #1 observation semantics -> #2 host diagnostics; independent
ZAW witness binding, LocalParse format selection, EvalFoundry no-clobber keys,
Terminus XI CI reference, AFR browser CI, Card-Forge schema coverage guard.
YELLOW workers return maps/diffs/tests; root monitors drift and owns publication.
Receipts: base/head commits, bounded diffs, regression results, push SHA, CI run.
Whole check: all pushed refs match audited content, stacked fixes compose, CI
is attached to those SHAs; disclose unavailable privileged/browser coverage.
Signals return to the owning local Stage 1; scope changes return to Ultra map.

## Cindermote #1 Stage 1
Base: 8ca4eba174f96d2ebca59e3b552f1037dd220dbb.
Missing/non-object/missing-status/unknown observation cannot prove completion.
Containment requires explicit COMPLETE and telemetry_incomplete is False.
Default ProbeResult observation is incomplete. Keep legacy receipt parsing
compatible; no new runtime or signing format. Update positive fixtures with
explicit proof. Regress absent/malformed proof and absent/incomplete telemetry.
Check focused incident gate tests and repository unprivileged suite, recording
privileged environment skips separately. Root reviews diff before publishing.

## Cindermote #2 Stage 1
After #1 passes, integrate its commit without rewriting history. Inspect both
mount paths; initialize mount proof false and set only after successful inspection.
Each independent OSError must return not-ready rather than an unbound-local crash.
Check positive host readiness and both failure branches, then suite and stack diff.

## Cindermote #1 Stage 2 / Stage 3 receipt
Changed only incident gate proof consumption and its fixtures/regressions.
Focused suite: 30 passed, 18 skipped, 12 subtests. Full CI-style suite: 241
passed, 24 skipped, 1 deselected, 125 subtests; one host tracer test failed
with ptrace EPERM in this container (unchanged tracer path). That host capability
is not repaired or disguised as a pass. CI must verify it on its normal runner.
Diff audit: missing/malformed observation becomes EVALUATION_INCOMPLETE;
telemetry requires literal False; historical receipt validator unchanged.
Local bounded regression PASS; full host execution remains CI/host-dependent.
The separately invoked root job-image contract also cannot complete here:
mkfs.ext4 exits 1 under this container. No production/test bypass was introduced;
normal CI's root job remains the required verification for that host operation.

## Cindermote #2 local Stage 1 amendment
First audit exposed a fixture issue: preflight also calls _mount_for for cgroups.
Isolate _cgroup_check in the mount regression fixture so each test controls only
the two mapped runtime mount inspections. No production scope amendment.

## Cindermote #2 Stage 2 / Stage 3 receipt
Integrated published #1 commit 9ac3297d2249a32e836995398b4641d6e2304213
onto #2 without rewriting either PR history. Mount proof booleans start False
and become true only after each successful inspection. Both independent OSError
branches return not-ready; positive two-mount and missing-noswap checks pass.
Focused combined suite: 59 passed, 18 skipped, 21 subtests; diff check clean.
#1 published CI passed both push/PR runs, including the host contracts that
could not execute in this local container. #2 will run those same gates anew.

Full locally runnable #2 suite: 247 passed, 24 skipped, 2 host-dependent tests
deselected (ptrace and root image contract as recorded above), 129 subtests.
