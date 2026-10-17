# Browser containment evidence — 2026-10-16–17

The final five-case gate passed at source
`6c9a0916fced21f179b0d1a42195c9f65813ca8f` on Void Linux `6.18.57_1`.
The pinned runtime was Firecracker/jailer `1.17.0`, guest Linux `6.1.188`, and
signed Debian Chromium headless shell `155.0.8059.79-1~deb12u1`.
Known newer browser advisories remain unresolved; this is bounded operational
proof, not hostile-production security clearance. See the
[audit and limits](../../2026-10-16-browser-gate.md).

## Signed run artifacts

| Gate file | Source | Result |
|---|---|---|
| `browser-gate-shell1.json` | `1d0966d` | `FAIL`: clean ALLOW and POST DENY, then incorrect WebSocket ALLOW. |
| `browser-gate-shell-csp.json` | `7a7ce9f` | `FAIL`: HTTP/2 empty-phrase navigation error, incomplete DENY. |
| `browser-gate-shell-csp-http2.json` | `1e2a80c` | `FAIL`: clean ALLOW and POST DENY, then incorrect WebSocket ALLOW; header-only CSP did not enforce the restriction. |
| `browser-gate-final.json` | `2fde077` | `FAIL`: old fixed-name RAM executables blocked upgraded startup; telemetry incomplete and purge unverified. |
| `browser-gate-final2.json` | `90e05b0` | `FAIL`: all five decisions matched and purge/telemetry verified, but one popup request reached the fixture. `fixture-counts-final2.json` is a separate host-signed post-run counter snapshot for the same instance. |
| `browser-gate-final3.json` | `6c9a091` | **PASS**: clean ALLOW; four expected DENYs; all shared counters zero; all streams/purge verified; 24 preflight and postflight checks passed. |

Final cases: clean `mf-web-5d992b85`; POST `mf-web-719798d3`; WebSocket
`mf-web-c1e5d937`; popup `mf-web-2f65fd6e`; unauthorized image
`mf-web-24c4858c`. Each has a signed `.json` receipt and
`.browser-evidence.json` sidecar. The five failed gates retain another 13
jobs and sidecars, including two false ALLOWs. A separate public example.org
smoke, `mf-web-2f9b79a1`, also completed with ALLOW and verified purge.

`browser-shell-local-verification.json` records local HMAC/schema, source-file,
receipt/evidence hash, exact-request reduction, and purge-field consistency
checks for all six gates and 18 jobs. Its final gate check also rehashes current
assets and checks current admission, counter metadata, and absence of stale
jobs. Historical build receipts match their gate hashes and declared image
hashes; superseded image bytes were not all rehashed. The separate
`public-smoke-local-verification.json` records the public smoke verification.
Verification reports are derived records, not third-party attestations.

## Builds and checks

`browser-rootfs-popup-no-cache-G.receipt.json` and its H counterpart are
byte-identical receipts from two fresh Docker builds on this host. Both the
image and receipt hashes matched:

```text
rootfs   7e49c47eedc089da8e87c2c7506fd5f3db9655f75904b47afe925a2b349a333d
receipt  bfe444ecaf9038f95fda49f2686cc0168115be455f8d5dd7b06d0dc2dc00e8a1
```

The G/H logs and `rootfs-popup-rebuild-comparison.json` preserve this check.
The final image stays local, outside Git. These are two builds on one host,
not independent-host reproducibility. Earlier E/F receipts, logs, comparison,
and the three historical browser build receipts explain the failed runs.
`staging-failure-diagnostic.json` and `staging-upgrade-verification.json` record
the old-pool mismatch and the real-root upgrade check.
`preflight-refresh-candidate.json` is the earlier E/F candidate admission check;
the final gate and `host-after-tests.json` contain the final image admission
checks. The latter also records stopped temporary helpers and no owned stale jobs.
A separate `--verify-output` process exited zero after fixture shutdown; its
console and exit status are retained.

The final `portable-tests-release-host.txt` records **522 passed**, **3 skipped**,
**348 subtests**, and **68.22% coverage** at `6c9a091`; `coverage-release.json`
contains its line-level report. The 3 skips require opt-in browser KVM, a live
provider credential, and root cgroup admission. The real browser gate was run
separately above. Earlier full-suite reports retain their source-stage counts. `static-checks.json` covers lint, the 17-file typed core,
kernel-laws, shell syntax, and all 95 tracked Python compilations at `6c9a091`.
`mutation-check.json` records that replacing explicit body fulfillment with
header-only CSP makes the preservation test fail. The production source was
not modified by that in-memory mutation. The real popup failure before the
native creation block remains published above.

## Checking these copies

From this directory:

```bash
sha256sum -c SHA256SUMS
```

This checks the published bytes against the index. Receipts use HMAC-SHA256
with a private host observer key; public readers cannot authenticate the
HMACs or establish independent execution without that key or external
attestation. A key holder can reproduce local verification against the exact
audited source, assets, retained receipts, and host prerequisites. The gate's
`--verify-output` command deliberately refuses a different Git HEAD, including
a later documentation or merge commit. The recorded verification ran before
those documentation commits. It does not re-contact the fixture.

Private observer/fixture keys, bearer tokens, raw diagnostic logs, page bodies,
and private guest material are excluded. The final control token traveled only
through certificate-verified loopback HTTPS; both public origin labels refer
to one shared fixture and are not independent counter witnesses. Retained
failures remain failures after later success. No new release, live-provider
agent ALLOW, general detection rate, or human security signoff is claimed.
