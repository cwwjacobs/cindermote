# Controlled-fixture browser evidence — 2026-10-16

This directory copies selected local proof byte for byte. The audited host was
Void Linux `6.18.57_1` with all 24 required Firecracker preflight checks
passing. The two temporary HTTPS origins served the same controlled fixture;
the private fixture token is absent from this bundle.

| Job | Retained files | Observed result |
|---|---|---|
| `mf-web-2cd1473a` | `browser-gate-candidate2.json`, receipt, browser evidence | Guest navigation failed with bounded `navigation_err_network_changed`. Signed `DENY`, incomplete telemetry, verified purge; gate `FAIL`. |
| `mf-web-0bf4c540` | `browser-gate-candidate3.json`, receipt, browser evidence | Firecracker browser navigation and sandbox succeeded, but one proxy tunnel was incomplete at teardown. Signed `DENY`, incomplete egress telemetry, verified purge; gate `FAIL`. |
| `mf-web-a2a77316` | `browser-gate-candidate4.json`, receipt, browser evidence | Navigation, attestation and all four streams completed; sandbox active and purge verified. Five Chromium background requests to unauthorized Google origins were blocked. Signed `DENY`; gate `FAIL` at its clean case. |
| `mf-web-b91adb3e` | `browser-gate-committed.json`, receipt, browser evidence | The same complete-but-`DENY` result was repeated against exact source commit `801b8037eaac04601a5ca9d8df7cf8f07b729c51`; the gate's provenance check passed. |

`browser-followup-local-verification.json` records the host-key check of all
four gate and receipt HMACs, schemas, evidence-file SHA-256 bindings, and
recomputed reductions. It also rechecks the committed run's source and assets
against that exact checkout. `browser-rootfs-candidate4.receipt.json` records the
pinned build inputs and the final rootfs digest. The image itself is retained
locally and is not in GitHub; two local builds reproduced its digest
`a83985565010ce930f10241bac06c0e550ca9b13b3a59dd9f52ef93214d19b7c`.
The second build used the same Docker cache and is not independent
reproducibility proof.

From this directory, anyone can check that the copied files still match this
published index:

```bash
sha256sum -c SHA256SUMS
```

The HMAC observer key, fixture token, raw Chromium diagnostic log, and any
private guest material were not published. A third party can inspect and hash
the public receipts, but cannot authenticate their HMACs or prove the host
execution independently without the host key or external attestation. The
gate's clean case failed, so its four adversarial cases were not run. No
browser `ALLOW`, five-case gate pass, new release, or live-provider agent
`ALLOW` is claimed. The [audit account](../../2026-10-16-browser-followup.md)
connects each result to the fixes and remaining blocker.
