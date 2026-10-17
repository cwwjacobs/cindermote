# 2026-10-16 audit evidence

This is a selected, byte-for-byte copy of the local audit's receipts, traces,
console results, and verifier outputs. `SHA256SUMS` indexes all 37 original copied
files plus the archived v1.3 policy (38 files total). The
[audit report](../../2026-10-16-security-audit.md) explains the findings and fixes;
[VALIDATION.md](../../../../VALIDATION.md) records the
commands and environment. Both failures and successes are retained.

| Run | What the retained evidence establishes |
|---|---|
| Legacy Incident Gate first run `run-20261016T065642Z-344a69dd` | All six child receipts verify, but the host-built snapshot could not start Python because `libpthread.so.0` was absent. The manifest has no `overall_status`; this is a failure, not containment success. |
| Legacy Incident Gate repaired run `run-20261016T070335Z-7351c694` | Six hostile probes completed with `DENY`, isolation and purge confirmed, and `ALL_BOUNDARIES_HELD`. The published run directory has its manifest, report, and six signed child receipts. |
| First privileged agent run `job-4d8fcdd89ab3ce1a` | Signed `INFRASTRUCTURE_FAILED` receipt and roads; cleanup verified, but guest and egress witnesses absent. The failure stage was not recorded. |
| Second privileged agent run `job-efad177c49dc0b70` | Signed `INFRASTRUCTURE_FAILED` receipt; the walked road identifies `proxy_setup` and `BrowserEgressWorkerProtocolError`. Cleanup verified. |
| Third privileged agent run `job-605f1a346b11ec76` | Signed `COMPLETE` receipt; guest, egress, and cleanup witnesses true; cleanup `VERIFIED`. The intentionally invalid provider key produced guest `PROVIDER_FAILURE` and gate `EVALUATION_INCOMPLETE`, so this is a jailed-runtime proof, not a model-task `ALLOW`. |
| Public-site browser smoke `mf-web-2af9af0e` | VM admitted and purge verified, but unauthorized background requests and telemetry loss led to fail-closed `DENY`. This is not the controlled-fixture browser gate. |
| Portable suite | `pytest-after-supported-host.txt` records 456 passed, 3 skipped, 191 subtests passed, and 67.32% coverage against a 60% floor. |

The agent receipts bind the three road files by hash. The
`supported-host-verification.json` output records the local check of receipt
and frozen-road HMACs, receipt-to-road hashes, evidence binding, and browser
receipt/evidence reduction. `evidence-manifest-final.json` indexes later audit
files as they existed at local audit commit `0526265`, including local items omitted
here. The linked audit report was subsequently edited to point to this public
bundle, so its current hash differs from that historical manifest entry. The
completed agent run's encrypted
guest evidence is retained locally with SHA-256
`a58a6c4e0afb0546e46fdc6aed075b68a39cd584ae63d322926a4fc22df455cf`;
it is not published because it is sealed private evidence.

From this directory, anyone can check the copied bytes:

```bash
sha256sum -c SHA256SUMS
```

The original host can also rerun the legacy HMAC/schema verifier against either
published run directory using its local `.observer_key`. Both runs bind the full
canonical v1.3 policy hash, so select the preserved policy explicitly rather than
the active policy (now v1.4):

```bash
python3 ../../../../scripts/verify-incident-gate-evidence.py \
  --policy hotcell-policy-v1.3.json --expect-all run-20261016T065642Z-344a69dd
python3 ../../../../scripts/verify-incident-gate-evidence.py \
  --policy hotcell-policy-v1.3.json --expect-all run-20261016T070335Z-7351c694
```

`hotcell-policy-v1.3.json` was added during the v1.4 migration as an exact copy
of the policy used by these runs. The original 37 checksum entries and all
retained receipts, manifests, reports, and verifier outputs are unchanged.
v1.4 only aligns the Firecracker declaration with agent-probe's existing routing;
it does not add central enforcement or new host proof. See
[policy versions](../../../../policy/README.md).

The observer key is deliberately absent from GitHub. Public hashes and HMAC
signatures allow inspection of the recorded data, but without that key or an
external attestor they do not independently prove what occurred on the host.
The controlled-fixture browser gate and a live-provider agent `ALLOW` remain
unverified. No new release is claimed.
