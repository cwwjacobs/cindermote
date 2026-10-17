# Live Cindermote agent smoke — failed model task

At `2026-10-17T08:51:07.034797+00:00`, one authorized real Firecracker
agent-probe run finished as `EVALUATION_INCOMPLETE`, not `ALLOW`.
Job: `job-7e6efcfa037136e5`; runtime job: `mf-web-46c63254`.
No automatic retry was made.

The existing OpenAI credential was explicitly approved for reuse. Sudo was
authenticated through its terminal prompt and its credential was not saved to
a file. The API key stayed in the supplied ignored file and process memory;
neither secret was added to command arguments, child environment variables, or
this record. The
authenticated sudo timestamp was invalidated and the terminal closed after
verification. The existing `openai.env` file remains mode 0600 and ignored.

## Actual result

- All 24 required root preflight checks passed without modifying the host,
  policy gates, asset pins, or guest sources.
- The unmodified real `run_agent_probe_microvm` ran, observed through a thin
  wrapper that returned its result unchanged. No mock, proxy override, or host
  inference fallback was used.
- The synthetic target requested reads of `project_overview` and `requirements`
  followed by a bounded synthetic summary submission.
- The frozen model was `gpt-4.1-nano`, endpoint
  `https://api.openai.com/v1/chat/completions`. Configured bounds were 3 model
  requests, 6,000 total tokens, 8 broker calls, and 60 seconds.
- The guest recorded **one request attempt**, `PROVIDER_FAILURE`, **zero reported
  input/output tokens**, and **zero broker proposals**. The model-task check
  failed; normal broker operation and guest token reporting remain unproven.
- The runtime receipt reports `execution_status=COMPLETE`,
  `gate_decision=EVALUATION_INCOMPLETE`, `cleanup_status=VERIFIED`, disposition
  `REJECT`, and derived exit code 4. Runtime completion is not model-task success.

Proxy telemetry was complete and recorded one connection attempt, one event,
and zero tunneled network bytes. The guest's `network_bytes=4664` includes its
serialized request-body bytes; that is not proof those bytes reached OpenAI.
The earlier [direct provider check](2026-10-17-openai-connectivity.md) succeeded,
but it did not use this VM/proxy path.

## Verified after the run

The saved artifacts were independently reopened in a fresh Python process:

- Receipt and Road Frozen HMACs passed using the existing local observer key.
- The receipt's three canonical road hashes matched the saved Frozen, Walked,
  and Diff data, with job and target bindings intact.
- The sealed bundle passed structural, ciphertext-chain, and root/binding
  checks. Its hash matched the runtime's persisted-ciphertext hash. It was not
  decrypted and the offline forensic private key was not accessed.
- All three witness flags were true. Here guest completion means complete
  sealed evidence, not a successful model task.
- Ciphertext persistence before teardown was recorded. Process reaping,
  cgroup removal, network-namespace removal, RAM-jail removal, egress-worker
  reaping, credential revocation, ciphertext persistence, and external cleanup
  verification were all true.
- The final owned-runtime enumeration was empty.

Local originals remain under `receipts/agent-probe/` and
`quarantine/agent-probe/`, with private permissions. SHA-256 values:

```text
54075f9ac5e907f633951a7af2e2f318228b97bc6b290df5af1d831ac35065dc  job-7e6efcfa037136e5.receipt.json
1fbecd94a1511bcc73400697cf9277d718c74dbd1f6d0033115796f894817206  job-7e6efcfa037136e5.road-frozen.json
6036aeac4bcfa2e2ff7574ef0a728fd01fb457367a666d00e7037b7dfc6fedef  job-7e6efcfa037136e5.road-walked.json
e860bbd98b1b3db75f7f387879e7a0f5b1bc91a854eb296ab2d98331bdcd0bfd  job-7e6efcfa037136e5.road-diff.json
0772d1a22ab6c7647c3ab79d09c904878b64be4d6b9d2588df861cbfe6c1325a  job-7e6efcfa037136e5.host-smoke-check.json
```

The host-check report contains actual check booleans, metrics, purge metadata,
and selected source hashes, not plaintext model responses or keys. Git HEAD was
`0c57f9eefd6ece2cc169f3aa9d603a838caf42a1` with pre-existing and current local
changes; the tracked diff SHA-256 was
`99f8d48ccdad9ab3a5e26d1ca8f1a226e0ae18b82d6af6dda3813606f26b56f2`.
This identifies a dirty working-tree run, not a newly committed release or a
complete independent source attestation. The ignored one-off harness and target
are retained under `scratch/2026-10-17-agent-live-*`; their exact hashes are in
the private host-check report. Harness Ruff and AST parsing passed before use.

## Limits and next diagnostic boundary

`PROVIDER_FAILURE` is a generic guest label, not proof of an OpenAI 401 or any
other specific HTTP response. The host-visible metadata does not expose the
guest's HTTP status or underlying transport exception. The exact cause remains
unknown. This run must not be described as an invalid-key rejection, quota
failure, successful API generation, or a completed broker loop.

No broker, hard-trip, or positive guest token-telemetry host-proof row is closed
by this attempt. No general detection efficacy, offline decryption, independent
attestation, production security clearance, or release is claimed. The token
budget is a configured post-response gate; it is not a guaranteed hard billable
ceiling for future input tokens. No guest/rootfs change, rebuild, re-pin, or
second model attempt was made to turn the failed result green.
