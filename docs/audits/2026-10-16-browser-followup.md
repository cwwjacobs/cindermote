# Controlled-fixture browser follow-up — 2026-10-16

The supported Void host (`6.18.57_1`) passed all 24 required Firecracker
preflight checks. Two temporary public HTTPS origins pointed to an
operator-controlled fixture; the gate verified that both served the expected
fixture source hash. The fixture control token stayed local. Each attempt
booted the pinned Firecracker/jailer/kernel and a newly built, hash-pinned
Chromium rootfs. The gate's clean case ran first and stopped the five-case
sequence when its expected `ALLOW` was not met.

| Image / job | What happened | Gate and cleanup |
|---|---|---|
| Candidate 2 / `mf-web-2cd1473a` | The guest reached `Page.navigate` but returned bounded `navigation_err_network_changed`. | `FAIL`; signed `DENY`, incomplete browser/CDP evidence; purge verified. |
| Candidate 3 / `mf-web-0bf4c540` | After the IPv4-only guest change, real Chromium committed the fixture navigation with its sandbox active. Five Google background requests were blocked; one allowed fixture tunnel was still open when the proxy stopped, so egress reported telemetry loss. | `FAIL`; signed `DENY`, incomplete egress evidence; purge verified. |
| Candidate 4 / `mf-web-a2a77316` | A bounded browser shutdown drain let the proxy record the fixture tunnel's normal close. Navigation, attestation, screenshot hashing, and all four evidence streams completed. Five Chromium startup requests to unauthorized Google origins were blocked by the proxy. | `FAIL`; signed `DENY`, **telemetry complete**, purge verified. The gate expected a clean-case `ALLOW` and did not run the remaining four cases. |
| Committed source / `mf-web-b91adb3e` | Repeated the candidate-4 result against exact source commit `801b8037eaac04601a5ca9d8df7cf8f07b729c51`; the gate's checkout, asset, and source provenance check passed. | `FAIL`; signed `DENY`, all four streams complete, purge verified. Five unauthorized background attempts remained blocked. |

The candidate-4 receipt reports the browser sandbox active, a read-only rootfs,
guest writes on tmpfs, VM admission, and externally verified teardown. Its
findings are five `web_blocked_egress_attempt` and five
`web_unauthorized_origin_attempt` events. The proxy's allowed target CONNECT
completed; none of the blocked Google attempts was allowed egress. They remain
findings because the browser made them. This is proof of real jailed browser
execution and fail-closed detection, **not** a clean browser gate pass or a
general safety verdict.

The changes under review are deliberately narrow:

- The Docker build context is an allowlist of pinned image inputs, so local
  observer keys, receipts, virtualenvs, and audit files are not sent to the
  Docker daemon with the build context.
- The guest allows Chromium's automatic same-origin HTTPS `/favicon.ico`
  request when CDP labels it `Other`; other unknown resource types remain
  blocked. Failures now report a bounded stage and code without returning URL
  text or page content.
- Guest init disables unused IPv6 before bringing up its IPv4-only network.
  Navigation succeeded after this change; the earlier network-change error
  alone does not prove IPv6 was its sole cause.
- Browser teardown schedules a half-second pause after stopping Chromium so the
  proxy can observe TCP close. A still-open tunnel continues to fail closed.
- The controlled HTTPS fixture can listen on local port 8443 while being
  published on port 443, and fixture tests cover that mapping.

The candidate-4 rootfs SHA-256 is
`a83985565010ce930f10241bac06c0e550ca9b13b3a59dd9f52ef93214d19b7c`;
its build-receipt SHA-256 is
`75e713f326a1384efd29ab4bb5f3cdf0d63261f2cb3420eaed688e37541c234b`.
A second build from the same pinned inputs reproduced both hashes exactly
using the local Docker cache. That comparison establishes repeatability here,
not an independent cold-cache or third-party rebuild.

The local verifier checked each of the four gate and job HMACs with the
host-only observer key, validated the receipt and evidence schemas, checked
the receipt-to-evidence SHA-256 bindings, and recomputed the evidence
reduction. It also rechecked the committed run against that exact checkout.
All checks passed. Selected byte-for-byte copies and a checksum
index are in the [public follow-up bundle](evidence/2026-10-16-browser-followup/README.md).
The originals, build logs, encrypted/private state, control token, observer
key, and raw Chromium diagnostic log remain local under `.cindermote/` or
`receipts/`. Published HMACs cannot be authenticated independently without
the host key.

The remaining gate blocker is Chromium's own background traffic on a fresh
profile. An isolated diagnostic with extra browser policies and feature flags
reduced those attempts but still produced `accounts.google.com` attempts;
those exploratory settings are not claimed as a production fix. A future
change must prevent the attempts or establish a separately auditable startup
phase without hiding page-driven attempts. Until then, the controlled fixture
gate and its four unrun adversarial cases remain unresolved. Hosted portable
tests do not replace this KVM gate.
