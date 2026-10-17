# Browser gate hardening — 2026-10-16–17

This follow-up replaces Chromium's desktop executable with Debian's
`chromium-headless-shell`. Initial diagnostic and retained failure runs used
`150.0.7871.124-1~deb12u1`; the final candidate refreshes it to the signed
`155.0.8059.79-1~deb12u1` package. The prior desktop process attempted Google background requests even
with background networking and sync disabled. The dedicated shell removes
those profile services; the proxy continues to record and deny unauthorized
traffic from the beginning of each job. No startup requests are exempted.
An [upstream browser-team investigation](https://github.com/microsoft/playwright/issues/42910)
describes the same desktop-service problem. The local VM runs, rather than
that upstream report, determine this audit's results.

## Verified outcome

The final gate **passed** on 2026-10-17 at exact source
`6c9a0916fced21f179b0d1a42195c9f65813ca8f`. The jailed guest used Chromium's
sandbox; all four evidence streams completed and every job's purge verified.
All 24 required preflight and postflight checks passed. Both labels reported
zero forbidden requests from the same authenticated fixture instance, using
certificate-verified loopback controls. The token was not sent to public origins.

| Case | Job | Signed decision |
|---|---|---|
| Clean | `mf-web-5d992b85` | `ALLOW` |
| POST | `mf-web-719798d3` | `DENY` |
| WebSocket | `mf-web-c1e5d937` | `DENY` |
| Popup | `mf-web-2f65fd6e` | `DENY` |
| Unauthorized image origin | `mf-web-24c4858c` | `DENY` |

A separate public `https://example.org/` smoke run, `mf-web-2f9b79a1`, also
received `ALLOW` with complete telemetry and verified purge on the same
source and assets. Local verification re-read all six retained gate HMACs,
18 gate-job receipts/evidence reductions, and the final current-source gate.
The public smoke receipt, evidence, exact request, and all six asset bindings
were checked separately. Historical build receipts were hash-bound to their
gates; not every superseded historical image remains available to rehash.
These are host-key-holder checks, not external authentication.

The [public bundle](evidence/2026-10-16-browser-gate/README.md) retains the
successful gate and all five failed gates below. Temporary fixture/tunnel processes were stopped afterward; the prepared host
still passed all 24 checks with no owned stale jobs. A separate offline gate
verification process passed after fixture shutdown. Operational success does
not remove the production security debt or the proof limits in this audit.

## Runtime freshness and remaining security debt

The final candidate pins Firecracker/jailer **1.17.0**, Linux **6.1.188**, and
Chromium headless shell **155.0.8059.79-1~deb12u1** from Debian snapshot
`20261016T120000Z`. The browser refresh closes older known version debt,
including the fixes tracked by [CVE-2026-16807](https://security-tracker.debian.org/tracker/CVE-2026-16807)
and [CVE-2026-17658](https://security-tracker.debian.org/tracker/CVE-2026-17658).
Version applicability is not a demonstration of an exploit against this
headless build, Chromium's sandbox, or Firecracker.

At review time, [Debian's tracker](https://security-tracker.debian.org/tracker/source-package/chromium)
listed 155.0.8059.79 as its current bookworm security package while still
listing open issues fixed upstream in 155.0.8059.84, including
CVE-2026-110913 through CVE-2026-110922. **The candidate retains known
upstream security debt and is not cleared for hostile production browsing.**
Fixture success cannot establish absence of exploitable browser defects.

The [official Firecracker release](https://github.com/firecracker-microvm/firecracker/releases/tag/v1.17.0)
archive's published SHA-256 and the extracted binary hashes were verified.
The guest kernel comes from a dated path in the official
[Firecracker CI bucket](https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20261016-5732b8331e1e-0/x86_64/vmlinux-6.1.188).
Its pin was computed from official HTTPS bytes; no publisher-signed kernel
checksum manifest was found. The hash pins subsequent use but is not an
independent build or signer attestation. [Kernel.org](https://www.kernel.org/)
already listed 6.1.190, two patch releases newer; comprehensive kernel CVE
clearance was not established.

## Source, rebuild, and portable checks

The refreshed candidate source is `2fde07773ad694737e084b5a409f73a4f4a74caa`;
its staging failure is retained below. The final host-test source is recorded
with the resulting gate artifact. The staging-repair source was
`90e05b065cda6d55494554da34c71b67dbc7651c`.
Two sequential `--candidate --no-cache` builds (E and F), with frozen inputs,
produced identical rootfs bytes and identical build receipts:

```text
rootfs   029a38758ad1b1798aa6ace3c392173476ea73f19b5275c59e62b799e077f455
receipt  9b8a8ba8ff884a6888c2153e23a6adcd7268d6473ed59b4715b969c371e082f2
```

Every source hash in the receipt matched the checkout before the deliberate
lock update. This is repeatability on one host with fresh Docker builds, not
an independent-host rebuild. The image remains local; both build logs,
receipts, and the comparison report are in the public bundle. A previous
150 build was interrupted for the security refresh and is not a final pass.

The refreshed candidate's full suite passed **510 tests and 313 subtests**, with **3 skips**
and **67.89% coverage** against the unchanged 60% requirement. The skips were
the opt-in browser KVM test, the live-provider agent test, and the root cgroup
test. The explicit privileged browser gate is recorded separately. Ruff,
the 17-file typed core, kernel-laws, shell syntax, and compilation of all 95
tracked Python files passed. A mutation check replaced body fulfillment with
the ineffective header-only path in memory: the preservation test failed,
then passed when restored; production source was not modified.

An earlier coverage run failed at 48.82% because it counted extracted vendor tools and
diagnostic Python under Git-ignored `.cindermote`. The source-only correction
excludes that generated directory, as lint already did; no production source
was excluded and the coverage requirement was not lowered. That failed run
and the restricted-environment test failure remain in the local audit log.

After the popup repair, two further `--candidate --no-cache` builds (G and H)
again matched both image bytes and build-receipt bytes. The reviewed final pin is:

```text
rootfs   7e49c47eedc089da8e87c2c7506fd5f3db9655f75904b47afe925a2b349a333d
receipt  bfe444ecaf9038f95fda49f2686cc0168115be455f8d5dd7b06d0dc2dc00e8a1
```

The final source/pin commit is `6c9a0916fced21f179b0d1a42195c9f65813ca8f`.
The popup-source suite at `336cc7c` passed **520 tests and 339 subtests**,
with **3 skips** and **68.23% coverage**. Later gate-only persistence tightening
discards reflected tokens, arbitrary text, malformed numeric values, and
unexpected keys from signed counter failure metadata. Assertions still use
the original response. Valid counters and instance IDs remain in the record;
strict integer zero is required in both the live and offline verifiers.

The staging-repair source's full suite passed **517 tests
and 328 subtests**, with the same **3 skips** and **68.24% coverage**. The
recorded static checks and all 95-file compilation were repeated against
`90e05b0`. The shared staging helper's file-level tests model root ownership
while exercising real links, modes, and bytes; the separate real-root check
verifies the actual installed pair and permissions.

The exact final source `6c9a091` passed **522 tests and 348 subtests**, with
**3 explicit skips** and **68.22% coverage** against the unchanged 60% gate.
The release console and coverage JSON are retained in the public bundle.

## Failures retained

| Source / gate | Result and retained jobs |
|---|---|
| `1d0966d` / `browser-gate-shell1.json` | Clean `ALLOW` (`mf-web-37583770`), POST `DENY` (`mf-web-683540f6`), then an incorrect WebSocket `ALLOW` (`mf-web-21321dae`). The gate correctly failed. Shared fixture counters read zero after this run; the false verdict demonstrates a missed attempt signal, not a demonstrated handshake escape. |
| `7a7ce9f` / `browser-gate-shell-csp.json` | Clean case `mf-web-a8d8d873` failed closed with incomplete telemetry during navigation. Chromium rejected an explicitly empty HTTP/2 status phrase in the response override. Purge verified. |
| `1e2a80c` / `browser-gate-shell-csp-http2.json` | The phrase repair restored clean `ALLOW` (`mf-web-e6350153`) and POST `DENY` (`mf-web-f19081df`), but WebSocket again incorrectly received `ALLOW` (`mf-web-c17de186`). The header-only CSP update did not enforce the added policy in the pinned browser. The gate failed and retained the failed job identity and hashes. |
| `2fde077` / `browser-gate-final.json` | Refreshed assets passed all 24 preflight checks, but clean job `mf-web-2eb2d41a` failed before jailer/proxy startup: the shared RAM staging filenames still held the old 1.16.1 binaries. Runtime refused the mismatched pool. Signed `DENY`, incomplete telemetry, and purge **unverified** (the absent proxy produced no reap witness). The preflight result was insufficient to establish executable startup. |
| `90e05b0` / `browser-gate-final2.json` | All five cases completed: clean `mf-web-36d8395a` was `ALLOW`; POST `mf-web-e77a104a`, WebSocket `mf-web-d85ed52b`, popup `mf-web-71a52357`, and unauthorized image `mf-web-4f37f8f0` were `DENY`. Every case had complete telemetry and verified purge. The overall gate still **failed**: a popup navigation reached the authorized fixture once. The separate signed `fixture-counts-final2.json` snapshot records `popup=1` and the same fixture instance, with the other counters zero. Child-target debugger pause/closure happened too late to prevent its first request. This is a forbidden passive interaction, not evidence of a VM escape. |

The [public bundle](evidence/2026-10-16-browser-gate/README.md) contains the
signed failures and their evidence sidecars. They remain failures even after
later changes succeed. Earlier background-traffic failures remain in the
[prior audit](2026-10-16-browser-followup.md).

## Defense and proof changes

The guest now starts Chromium with `--block-new-web-contents`, preventing
new-window creation in the browser process before navigation. The pinned
[headless implementation](https://chromium.googlesource.com/chromium/src/+/155.0.8059.79/headless/lib/browser/headless_web_contents_impl.cc#216)
applies that option to creation and its `OpenURLFromTab` path. Blink emits
the [native WindowOpen probe first](https://chromium.googlesource.com/chromium/src/+/155.0.8059.79/third_party/blink/renderer/core/page/create_window.cc#324),
so attempted popup metadata remains observable. A private diagnostic showed
that signal, one allowed proxy connection, and zero shared counters; it used
`--no-sandbox` and is explicitly **not** sandbox or VM proof. The real gate
must establish the production result. Reusing an existing named frame is
outside new-context prevention and still depends on navigation interception.

Both browser and agent profiles now select a staging directory identified by
the Firecracker/jailer hash pair. Existing flat or older-pair files stay
untouched. Root-owned private directories and regular root-owned `0500`
executables are required; hashes are checked through non-following file
descriptors. Verified temporary bytes are published without replacing an
existing executable, and a concurrent winner is rechecked. Corrupt selected
bytes fail closed. The real-root staging check verified the new pair and
unchanged legacy files before the next VM attempt; it makes no VM claim.

The collector now intercepts document responses and obtains strict base64
content-decoded body bytes. It preserves those bytes, status, content type,
and existing policies, adds an explicit-origin `connect-src` CSP, then supplies
the body through `Fetch.fulfillRequest`. Compression, transfer framing, and
length headers are adjusted for the decoded body. Header-only overrides did
not enforce the new policy in local diagnostics; explicit body fulfillment
produced a native CSP violation and no WebSocket connection in that same
diagnostic. Chromium's [interceptor implementation](https://raw.githubusercontent.com/chromium/chromium/9261fd0a595ac4964ea84e6bd4a025c1173a2ffa/content/browser/devtools/devtools_url_loader_interceptor.cc)
also distinguishes the fresh response-head path from the header-only path.

Explicit HTTP(S) origins exclude WebSocket schemes; adding a second CSP
preserves existing server restrictions. Native CSP audit violations and
WebSocket/WebTransport creation events contribute attempt metadata without
retaining raw URLs, headers, or body content in evidence. This uses
[CSP scheme matching](https://www.w3.org/TR/CSP3/#match-schemes) and the
[Fetch protocol](https://chromedevtools.github.io/devtools-protocol/tot/Fetch/).

Observation ends at a frozen load-event snapshot. DevTools stays attached
until confirmed Chromium termination. If killing or reaping Chromium fails,
the collector retains the process and socket, reports failure, and waits for
the host to stop the proxy and terminate the microVM. It also holds if sending
the failure result fails. A child-process regression checks that a catchable
Python interruption cannot release this hold.

The gate binds each signed receipt to the exact request URL/hash, origins,
mode, budgets, and all six runtime asset digests (Firecracker, jailer, kernel,
browser, rootfs, and build receipt). It rejects reused job IDs and includes failed-case job and
artifact hashes in signed failures. In private-control mode, both public fixture origins must match
the authenticated loopback endpoint's random instance ID and source hash.
Counter responses carry that ID to detect a restarted fixture supplying fresh
zeros. Both origin labels refer to one shared fixture instance.

Fixture identity is public metadata; the control token travels only over
certificate-verified loopback HTTPS in the final run. Control redirects and
environment proxies are disabled. The older audit's statement that the
historical token stayed local has been corrected: those runs excluded the
token from published artifacts but sent it through public tunnel endpoints.

## Limits of this proof

- A five-case result covers the clean page, POST, WebSocket, popup, and
  unauthorized image-origin fixtures on this host and pinned source/image.
  It does not measure general detection efficacy or cover WebRTC and every
  native transport. WebTransport creation observation alone does not prove
  WebTransport prevention.
- Document bodies must be nonempty, unambiguously base64 encoded, and no
  larger than 4 MiB or the smaller requested network budget. Empty,
  malformed, oversized, or unavailable bodies fail closed. Chromium buffers
  a body before the collector validates its size; VM, CDP, network, and time
  limits are the outer bounds.
- Preserved bytes are content-decoded bytes, not compressed wire bytes.
  Synthetic response fulfillment changes transport metadata and streaming
  behavior. The collector does not independently establish body integrity
  beyond the bytes returned by Chromium.
- Delayed behavior after the frozen load snapshot is outside observation.
- Local HMAC verification requires the private host observer key. Published
  hashes check artifact bytes; they are not external authentication or a
  third-party witness. Two builds on the same host are not an independent
  rebuild. Automated source review is not human security signoff.
- A live-provider agent `ALLOW`, a run dashboard, and a New Run button are
  separate, unimplemented or unverified outcomes; the documented commands
  already create distinct browser jobs and allow receipt inspection.
