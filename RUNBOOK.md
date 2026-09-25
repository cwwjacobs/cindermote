# Cindermote Hotcell Runbook

Run commands from the repository root.

## Runtime profiles

- `browser-probe` is the competition isolation path. It requires Firecracker,
  jailer, KVM, a dedicated RAM runtime, cgroup v2, and the host egress broker.
  Failure has no namespace fallback.
- The Python, shell, skill, tool-definition, and MCP runners remain the legacy
  namespace profile. Their receipts identify that boundary explicitly.

Firecracker implements build issue 6, fail-closed isolation. The bounded
headless browser is the issue 8 artifact/tool profile; it is not ambient
networking for arbitrary artifacts.

## Provision pinned Firecracker assets

```bash
./scripts/fetch-firecracker.sh
```

This installs and verifies:

- Firecracker `1.16.1`;
- the matching `jailer`;
- the Firecracker CI Linux `6.1.155` guest kernel.

The expected release and binary hashes live in
`policy/firecracker-assets.lock.json`. Runtime admission recomputes them; it
does not resolve `latest`.

## Build the headless Chromium guest

Docker is a build-time tool only. It is not in the runtime trust boundary. A
clean checkout does not contain the ignored `.cindermote/cache` artifacts, so
it must reconstruct them before preflight. The host needs Docker, Python 3,
and standard coreutils; the exact ext4 tools do not come from the host.

```bash
./scripts/build-firecracker-image.sh
```

The builder uses a digest-pinned Debian base, Debian snapshot
`20260716T110000Z`, Chromium `150.0.7871.124`, and its setuid sandbox helper.
It builds a separate, pinned filesystem-toolchain container containing
`e2fsprogs 1.47.0-2+b2`, `fakeroot 1.31-1.2`, and an exact SHA-256-verified
`e2fsdroid`. Filesystem construction then runs offline, unprivileged,
capability-free, and read-only except for its scratch bind mount. It emits:

```text
.cindermote/cache/images/browser-rootfs.ext4
.cindermote/cache/images/browser-rootfs.receipt.json
```

The receipt binds the ext4 hash, Chromium version and binary hash, the actual
root-owned `04755` sandbox inode, every pinned build input, checked-out guest
and builder source hashes, the fixed source epoch/filesystem UUID/directory
hash seed, read-only-root requirement, and tmpfs-only guest writes. It does
not bind a Docker manifest ID: that metadata may vary even when the resulting
filesystem bytes do not.

The normal command succeeds only when both output hashes match
`policy/firecracker-assets.lock.json` exactly. A mismatch is a release failure.
`--candidate` prints unmatched hashes only for an intentional new release; it
does not make those bytes admissible. Repinning requires two identical cold
builds, the full tests, and deliberate Operator review.

For a release reproducibility check, build twice without Docker layer reuse
and compare both byte strings:

```bash
repro_cache="$(mktemp -d /tmp/cindermote-rootfs-repro.XXXXXX)"
./scripts/build-firecracker-image.sh --no-cache
CINDERMOTE_CACHE_DIR="$repro_cache" \
  ./scripts/build-firecracker-image.sh --no-cache

cmp --silent \
  .cindermote/cache/images/browser-rootfs.ext4 \
  "$repro_cache/images/browser-rootfs.ext4"
cmp --silent \
  .cindermote/cache/images/browser-rootfs.receipt.json \
  "$repro_cache/images/browser-rootfs.receipt.json"
```

Both comparisons must return zero, and both SHA-256 values must equal the
checked-in `browser_rootfs` pins. Network or archive disappearance fails the
build; it never permits substitution or resolution of `latest`.

## Prepare a Firecracker host

The competition host target is Linux `6.18.x`: it is both a Firecracker-tested
family and supports the tmpfs `noswap` control used here. Preflight verifies
the operative requirement directly — it re-reads the runtime and jailer mount
options from `/proc/self/mounts` and admits only a host whose real mounts
prove `noswap` (the kernel rejects unknown tmpfs options, so a mounted
`noswap` tmpfs is direct evidence); kernels outside the tested family are
admitted on that proof. The host must expose
`/dev/kvm` and `/dev/net/tun` and delegate a writable cgroup v2 hierarchy.
Disable host swap before preparation; this is mandatory, not a warning.

```bash
sudo ./scripts/prepare-firecracker-host.sh
sudo /usr/bin/python3 ./mote/detonate.py --firecracker-preflight
```

Preparation mounts `/run/cindermote` as root-only `tmpfs` with
`nosuid,nodev,noswap`. A nested root-only RAM mount at
`/run/cindermote/jailer` permits only the device nodes jailer must create while
retaining `nosuid,noswap`; this keeps the rest of the runtime `nodev`. It also
provisions locked, non-login `cindermote-vmm` and `cindermote-proxy` user/group
pairs and prepares delegated CPU, memory, and PID cgroups. Their numeric IDs
must be unique and disjoint from each other, root, `nobody`, and every other
host account/group. The VMM, TAP, and jail assets use the former; the egress
parser drops irreversibly to the latter. Preflight re-resolves both identities,
mount ownership/modes, and cgroup delegation and must print `"ready": true`
before a browser job is admitted.

### What “the VM is in RAM” means

The pristine, hash-pinned asset cache may live on disk. For every admitted
job, the runtime copies the Firecracker binary, guest kernel, read-only rootfs,
job drive, sockets, logs, and serial output into `/run/cindermote`. Guest RAM is
anonymous host memory. Guest `/run`, `/tmp`, `/home/probe`, the Chromium
profile/cache, and `/dev/shm` are bounded tmpfs mounts.

Host swap must be disabled, the runtime tmpfs must use `noswap`, and the VM
cgroup sets `memory.swap.max=0`. Core dumps are disabled for the supervised
VMM. No Firecracker memory snapshots are created in v1. These requirements are
what make the claim RAM-confidential; tmpfs by itself would not.

## Run one passive website probe

The initial URL is authorization, not untrusted input discovered by the page.
Only its exact web origin is allowed by CDP unless more origins are listed
explicitly. For HTTPS, the host proxy separately authorizes only the CONNECT
host and port; it does not observe the encrypted web origin.

```bash
sudo /usr/bin/python3 ./mote/detonate.py \
  --browser-url 'https://site-authorized-by-the-operator.example.org/'
```

For a site that legitimately needs additional origins:

```bash
sudo /usr/bin/python3 ./mote/detonate.py \
  --browser-url 'https://app.example.org/' \
  --authorized-origin 'https://app.example.org' \
  --authorized-origin 'https://static.example.org'
```

Do not put secrets in URL query strings. The receipt stores a URL hash and
normalized origins, not the full URL, but the full URL necessarily exists in
the ephemeral job drive while the browser runs.

The same request can be supplied as a `browser-probe` JSON artifact conforming
to `schemas/browser-probe-v1.schema.json`.

## Browser and network boundary

The browser profile is passive:

- one primary tab; GET/HEAD only for an explicit passive CDP resource-type
  allowlist—WebSocket, WebTransport, EventSource, Ping, preflight, CSP-report,
  and unknown resource types are blocked even when their handshake says GET;
- Chromium auto-attaches every child page, iframe, service worker, and worker
  with `waitForDebuggerOnStart`; the collector closes it while still paused
  and never resumes it;
- no clicks, typing, uploads, downloads, popup grants, or permission grants;
- fresh profile and cache for every VM;
- the trusted evidence collector remains guest root, is non-dumpable, and
  launches sandboxed Chromium as UID 1000 so browser content cannot ptrace or
  signal the collector;
- target-page metadata is collected from a bounded isolated DevTools world
  only after the matching target loader reports its lifecycle `load` event;
- Chromium denies all permission prompts; v1 does not claim a separate signal
  for each permission request;
- CDP listens only on guest loopback and is never exposed to the host network;
- raw DOM, page text, console strings, TLS bytes, and screenshots do not enter
  the signed outward receipt.

The guest has no general internet route, direct DNS, UDP, QUIC, or WebRTC
egress. Its only routed destination is the host proxy at
`169.254.250.1:18080`. The parser runs outside the root orchestrator in a
separately exec'd `cindermote-proxy` process with parent- and child-verified
UID/GID, zero capabilities, no-new-privs, non-dumpable state, an empty
environment, bounded resources, and a nonce-bound lifecycle receipt. Its
listener teardown tracks and boundedly joins every accepted handler before
claiming complete telemetry. It pre-resolves every authorized hostname,
rejects unsafe IP ranges, pins accepted addresses, checks the exact guest peer,
and enforces byte, connection, header, event, and time budgets. For plain HTTP
it also observes and enforces the request origin. For HTTPS it observes and
enforces only CONNECT host:port and the connected pinned peer. MMDS is disabled.

HTTPS remains end-to-end; the host proxy cannot inspect methods inside a TLS
tunnel after a hypothetical full browser compromise. CDP enforces passive
methods during normal operation, and Firecracker contains the browser if that
guest-side control is defeated.

## Evidence and “corruption” terminology

The output is browser content-risk evidence, not proof that a website is
“corrupt.” Deterministic signals include visible/hidden prompt-like markers,
unauthorized CDP web origins, unauthorized proxy HTTP origins or CONNECT
authorities, popup/download/upload attempts, mixed content, browser-sandbox
failure, and telemetry loss in either independent witness stream.

Each signed receipt contains hashes and reductions. The complete metadata-only
event bundle is stored beside it as:

```text
receipts/<job-id>.browser-evidence.json
```

The bundle uses `cindermote.browser-evidence/v2`: `web_origin` is a CDP or
plain-HTTP proxy observation, while `connect_authority` is HTTPS proxy
transport evidence. Receipt labels preserve the same distinction. Its SHA-256
is signed into the receipt. Any schema error, sequence gap, count
mismatch, missing lifecycle event, missing sandbox attestation, incomplete CDP
or proxy telemetry, VMM error, proxy failure, or incomplete purge forces `DENY`.
An `ALLOW` override cannot bypass infrastructure fail-closed findings.

## Teardown

After success, timeout, or fault, the host first revokes and independently
proves the egress worker was reaped, then kills the supervised VMM process
group and job cgroup, removes
TAP/veth devices and the network namespace,
checks that the cgroup is unpopulated, removes the cgroup, and deletes the RAM
jail. A minimal parent-death supervisor kills the jailer/VMM group if the
orchestrator itself dies; the next admission reconciles only exact
`mf-web-<8 hex>` stale resources while holding the global browser lock. The
Policy Gate runs on the post-purge result.

## Legacy namespace runner

Bootstrap its minimal snapshot:

```bash
python3 ./mote/detonate.py --bootstrap-snapshot
```

Run an artifact:

```bash
python3 ./mote/detonate.py \
  --artifact ./path/to/artifact.py \
  --artifact-type python-script
```

Valid legacy types are `mcp-server`, `tool-definition`, `skill-md`,
`python-script`, and `shell-script`.

## Verification

Pure Firecracker/API/browser-contract/proxy tests do not require KVM or visit a
website:

```bash
python3 -m unittest discover -s tests/firecracker -p 'test_*.py' -v
```

The legacy root-required suite is:

```bash
python3 ./tests/test_runner.py
```

### Required supported-host competition gate

The real suite uses two operator-controlled public DNS names and a publicly
trusted TLS certificate covering both names. Both may resolve to one fixture
server. They must be genuinely reachable through the production resolver and
proxy; substituting localhost or a private address would bypass the SSRF and
egress controls the suite exists to prove.

On the controlled fixture host, create a private 32-byte-or-larger URL-safe
token file, then run:

```bash
sudo /usr/bin/python3 tests/firecracker/fixture_https_server.py \
  --bind 0.0.0.0 \
  --port 443 \
  --certificate /path/to/fullchain.pem \
  --private-key /path/to/privkey.pem \
  --primary-origin 'https://probe-fixture.example.org' \
  --unauthorized-origin 'https://probe-secondary.example.org' \
  --control-token-file /run/secrets/cindermote-e2e-token
```

Place the same token in a root-readable `0600` file on the supported KVM host.
Run the canonical gate directly:

```bash
sudo /usr/bin/python3 tests/firecracker/e2e_supported_host.py \
  --origin 'https://probe-fixture.example.org' \
  --unauthorized-origin 'https://probe-secondary.example.org' \
  --control-token-file '/run/secrets/cindermote-e2e-token' \
  --output receipts/firecracker-e2e-gate.json
```

Then independently verify the persisted result immediately before submission:

```bash
sudo /usr/bin/python3 tests/firecracker/e2e_supported_host.py \
  --verify-output \
  --output receipts/firecracker-e2e-gate.json
```

The suite boots the pinned Firecracker/Chromium image for five cases. It
requires clean HTTPS navigation to `ALLOW`; blocks POST, WebSocket, popup, and
unauthorized-origin attempts; checks the fixture saw zero forbidden actions;
verifies each signed metadata receipt; and independently confirms the VMM,
egress worker, cgroup, network namespace, veth, and RAM jail are gone. Its
machine-readable gate result is preserved at
`receipts/firecracker-e2e-gate.json`.

The gate result binds Git `HEAD` and a deterministic content manifest of the
entire scoped runtime/test source surface, including dirty and untracked
files. It separately records the fixture source hash, policy and asset-lock
hashes, and the cache-relative browser-rootfs and build-receipt hashes. Both
fixture origins must report the same fixture source hash, and the gate
recomputes the complete provenance bundle after teardown; any mutation forces
`FAIL`. The result's HMAC authenticates it only to a holder of this host's
local observer key. It is explicitly not a third-party signature or externally
verifiable build attestation. Verify-on-read rechecks that HMAC, current scoped
source/assets/rootfs provenance, all five persisted signed case receipts and
evidence reductions, zero forbidden-action counts, current preflight, and the
absence of stale jobs. It does not re-contact the fixture.

This checkout's current container cannot execute that gate because KVM, TUN,
writable cgroups, nested tmpfs device support, swap control, and the required
Linux 6.18 host are not exposed. A competition submission must not claim the
gate passed unless the direct gate exits zero, its newly written artifact
records `"status": "PASS"`, and a separate `--verify-output` invocation exits
zero immediately before submission. Reading `"status": "PASS"` alone is not
sufficient. No other kernel family is admitted by the competition profile.

## Agent-probe v0

The complete agent-probe runbook is in `docs/agent-probe/RUNBOOK.md`. This
profile shares the pinned Firecracker rootfs and privilege-separated CONNECT
proxy with browser-probe, but dispatches the trusted guest agent based on the
read-only job manifest. Rebuild and deliberately repin the rootfs after adding
agent-probe sources; the old browser-only image is intentionally rejected.
