# Policy versions

`hotcell-policy.json` is the active policy, currently
`cindermote-hotcell-v1.4`. This version adds `agent-probe` to the Firecracker
`required_for` declaration; all other policy settings are unchanged from v1.3.

This is declaration alignment, not new runtime enforcement. No runtime reads
`required_for`. Agent-probe already defaults to `run_agent_probe_microvm` in
`agent_probe/runner.py`, whose Firecracker runtime rejects an unready preflight
without a namespace or host-inference fallback. This version change supplies no
new host proof of the broker loop, hard-trip cutoff, or token telemetry.

## Historical receipt verification

Legacy Incident Gate receipts bind the full canonical policy hash. Changing even
the policy version makes an old receipt fail verification against the active
policy; verification must use the exact policy from its run, not weaken that
binding or rewrite the receipt.

The two published October 16 Incident Gate runs (12 child receipts) used v1.3.
Its exact bytes are preserved as
[`hotcell-policy-v1.3.json`](../docs/audits/evidence/2026-10-16/hotcell-policy-v1.3.json)
beside the evidence, and included in that bundle's `SHA256SUMS`:

- File SHA-256: `f4b635ec81370ab9892b5f7c1a765b80007265ecea4d7f14d6600e37ad370396`
- Canonical policy SHA-256: `2bcf44a667a9dc7059b9cf0bf40bb3b981e9953b7f82b55e92d18c3930bb238b`

Keep this archive unchanged. The [published verification commands](../docs/audits/evidence/2026-10-16/README.md)
select it explicitly with `--policy`; the verifier still requires the original
host's private observer key to authenticate the published HMAC signatures.
Portable tests instead use temporary copies re-signed with a test-only key and
do not establish the original host's behavior or authenticate its HMACs.

Browser-gate verification additionally binds the exact source tree and policy
bytes. The historical browser gate remains proof of its recorded source, not a
fresh gate for v1.4; its current-source provenance checks are not bypassed.

For future policy revisions, retain the prior policy and pin historical
verification instructions before changing the active file. The verifier's
default remains the active policy for new runs.
