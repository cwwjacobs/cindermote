# Contributing

Cindermote is a security tool whose value is that its claims are true. Changes are
welcome when they keep that property: a claim in the README needs a test that can
fail, and a failure to observe something is a failure, never a pass.

## Setup

Linux, Python 3.11, 3.12 or 3.13, system `libsodium`, and:

```bash
python3 -m pip install pytest pytest-cov cryptography ruff mypy
```

Clone with `umask 022`, or run `chmod -R go-w .` afterwards. Debian and Ubuntu
default to umask 002, which makes files group-writable, and the trusted-source
gates refuse such files (the error names the file).

## Checks

These are the commands CI runs ([ci.yml](.github/workflows/ci.yml)):

```bash
python3 -m compileall -q .
ruff check .
mypy cli.py kernel_laws.py agent_probe/contract.py agent_probe/receipt.py   # full list in ci.yml
python3 cli.py kernel-laws
python3 -m pytest -q tests \
  --deselect=tests/test_agent_probe_runtime_protocol.py::test_job_image_copies_opaque_target_without_parsing \
  --cov --cov-report=term-missing:skip-covered
```

The coverage gate (`fail_under` in `pyproject.toml`) is a ratchet. Raise it when
coverage rises; do not lower it to land a change.

Tests that need KVM, root, a writable cgroup v2 mount or a live provider skip when
the host cannot run them. A skip is not coverage. The privileged runs are in the
manual [supported-host workflow](.github/workflows/supported-host.yml).

## Hash-pinned guest sources: read before editing

The runtime refuses to start a microVM unless these files match the SHA-256 values
recorded in the guest rootfs build receipt (`mote/firecracker_runtime.py`,
`_rootfs_receipt_check`):

```text
guest/agent_probe_agent.py          guest/browser_agent.py          guest/cindermote-init
agent_probe/__init__.py             agent_probe/canonical.py        agent_probe/evidence.py
agent_probe/hpke.py                 agent_probe/protocol.py         agent_probe/secretstream.py
mote/browser_contract.py
images/firecracker/Containerfile    images/firecracker/RootfsToolchain.Containerfile
scripts/build-rootfs-in-toolchain.sh   scripts/build-firecracker-image.sh
```

Any edit to one of them, including a formatter or an unused-import cleanup, makes
supported-host admission fail until the rootfs is rebuilt and re-pinned
(`./scripts/build-firecracker-image.sh --candidate --no-cache` twice, compare, review,
then update `policy/firecracker-assets.lock.json`; see
[docs/agent-probe/RUNBOOK.md](docs/agent-probe/RUNBOOK.md)). That needs Docker and a
KVM host. Batch such edits, and say in the pull request that a re-pin is required.
`pyproject.toml` exempts the two guest agents from the `F401` lint rule for this
reason. Put new host-side behavior in host-only modules instead.

## Rules of the road

- **Fail closed.** Unknown input, a missing witness or an unreadable file must
  produce a denial or an "incomplete" result, never an allow.
- **Verifiers never raise on hostile input.** Anything read from a receipt or
  evidence file that is malformed is "invalid".
- **No unwired code that looks like a feature.** A module that no entry point calls
  is marked `reference` in [FIELD_ATLAS](docs/FIELD_ATLAS.md) (checked by
  `cindermote kernel-laws`) or deleted.
- **Tests must be able to fail.** Prefer a test that mutates its input and asserts
  the rejection over one that asserts a constant. Mutate the code under test once
  to confirm the test notices.
- **Do not add provider-specific defaults.** Endpoints and models are explicit.
- Do not commit generated state: the legacy snapshot, receipts, quarantine output,
  keys or caches (all covered by `.gitignore`).

## Reporting security problems

Not here; see [SECURITY.md](SECURITY.md).
