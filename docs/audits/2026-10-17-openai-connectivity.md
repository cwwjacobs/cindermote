# Direct OpenAI connectivity check — 2026-10-17

This is a direct provider diagnostic, **not a Cindermote guest or broker run**.
Corey explicitly approved reusing the existing `openai.env` credential. Its
contents were parsed locally without shell sourcing and were not printed,
included in command arguments, exported to a child environment, or recorded
here. Only synthetic check text and a synthetic function schema went to OpenAI.

## Observed results

An authenticated `GET https://api.openai.com/v1/models` returned HTTP 200 and
listed `gpt-4.1-nano`. A single Chat Completions generation request then used
`gpt-4.1-nano`, `temperature: 0`, `max_tokens: 64`, `store: false`, and a forced
synthetic `report_smoke` function with one boolean argument. No function was
executed, and no tool result or follow-up model request was sent.

```json
{
  "utc": "2026-10-17T08:00:20.809996+00:00",
  "scope": "DIRECT_PROVIDER_ONLY_NOT_CINDERMOTE_GUEST",
  "http_status": 200,
  "model": "gpt-4.1-nano-2025-04-14",
  "request_id": "req_0ea10d31675342c6a499da1b576fe5de",
  "generation_request_count": 1,
  "retries": 0,
  "max_output_tokens": 64,
  "latency_ms": 1998,
  "tool_proposal_schema_passed": true,
  "tool_execution_count": 0,
  "token_usage_present": true,
  "usage": {
    "prompt_tokens": 75,
    "completion_tokens": 5,
    "total_tokens": 80
  }
}
```

The schema check required exactly one `report_smoke` proposal whose arguments
parsed as `{"ok": true}`. Usage checks required positive integer input, output,
and total counts. Both passed against the actual provider response. HTTPS
certificate validation was enabled; redirects, environment proxies, and retries
were disabled. No real target artifact, conversation, or private task data was
sent. Provider-side retention remains an external boundary; `store: false` is
not a claim of zero retention.

The request shape was checked against the official
[Chat Completions reference](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create),
[model-list reference](https://developers.openai.com/api/reference/resources/models/methods/list),
and [GPT-4.1 nano documentation](https://developers.openai.com/api/docs/models/gpt-4.1-nano).
The request uses the same API family as the current guest, but forcing this
synthetic function is not a behavioral evaluation of the guest's automatic tool
selection.

## Credential and release protection

`openai.env` initially had mode 0644 and was not ignored. It now has mode 0600
and matches the added `*.env` Git ignore rule. The release packager copies files
independently of Git, so it now explicitly excludes `.env`, `.env.*`, and
`*.env` at any depth as well. This does not establish that a formerly readable
key was never accessed, and no existing key was rotated or replaced.

`tests/test_release_secret_exclusions.py` checks the actual rsync argument block
and includes synthetic-project archive and mutation regressions using only fake
credentials. The argument check passed; disposable in-memory mutations removing
each of the three exclusions were all caught, even with misleading comment
text left behind. The two actual archive tests skipped
because this host has no `rsync`; no real working-tree release was packaged.

Together with the preceding policy/key/receipt tests:

```bash
.venv/bin/python -B -m pytest -p no:cacheprovider -q \
  tests/test_release_secret_exclusions.py tests/test_policy_versioning.py \
  tests/test_receipt_verification.py tests/test_agent_probe_runner.py \
  tests/test_incident_gate.py \
  --deselect=tests/test_incident_gate.py::TestCinderProbeIntegration \
  --deselect=tests/test_incident_gate.py::TestObservationFailureDetonation
```

Result: **133 passed, 2 skipped, 18 deselected, 18 subtests passed**. Ruff,
`bash -n scripts/package-release.sh`, and `git diff --check` passed.

## What remains unproven

`sudo -n true` returned "a password is required". No privileged Cindermote run
was attempted and no authorization boundary was bypassed. This direct check
does not exercise Firecracker, namespace isolation, proxy pinning, vsock key
delivery, the host broker loop, hard-trip cutoff, guest token telemetry,
encrypted evidence, cleanup, or signed receipts. The Stage 3 host ledger and
its earlier invalid-key run remain unchanged. No current-source host gate,
production security clearance, release, commit, or push is claimed.
