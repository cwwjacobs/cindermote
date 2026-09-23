# agent-probe v0 runbook

Run from the repository root.

## 1. Generate keys

Keep the forensic private key outside the repository and preferably offline.

```bash
python3 scripts/generate-agent-probe-keys.py \
  --offline-private-key "$HOME/offline/cindermote-agent-probe.x25519.key"
```

This creates `.observer_key` and
`policy/agent-probe-quarantine.x25519.pub`. Secret files are ignored by git.

## 2. Rebuild and deliberately pin the dual-profile rootfs

The agent guest and exact cryptographic dependencies changed the rootfs source
attestation. Build twice from cold caches, compare both ext4 images and receipts,
review the hashes, and then deliberately update the two `browser_rootfs` hashes
in `policy/firecracker-assets.lock.json`.

```bash
./scripts/build-firecracker-image.sh --candidate --no-cache
```

Candidate mode does not admit the image. Normal mode must reproduce the pinned
hashes exactly.

## 3. Prepare and preflight the host

```bash
sudo ./scripts/prepare-firecracker-host.sh
sudo python3 - <<'PY'
from cindermote.mote.firecracker_runtime import preflight_firecracker
import json
print(json.dumps(preflight_firecracker(profile="agent-probe").to_dict(), indent=2))
PY
```

All mandatory checks must pass: root, KVM, TUN, locked Firecracker/jailer/kernel,
attested rootfs, dedicated VMM/proxy identities, RAM runtime, disabled swap, and
delegated cgroup v2.

## 4. Run one target

The endpoint must be OpenAI-compatible and HTTPS. Pass the credential through a
pipe, not the environment:

```bash
printf '%s' "$FRESH_ONE_RUN_API_KEY" | \
  sudo env \
    CINDERMOTE_AGENT_PROBE_ENDPOINT='https://api.provider.example/v1/chat/completions' \
    CINDERMOTE_AGENT_PROBE_MODEL='provider-model-id' \
    CINDERMOTE_AGENT_PROBE_API_KEY_FD=0 \
    python3 cli.py detonate ./target.skill agent-probe
```

Only the descriptor number enters the environment. The credential bytes travel through stdin and are zeroed from the runner's mutable buffer after one-shot delivery.

Outputs:

```text
quarantine/agent-probe/<job>.guest-evidence.json.enc
receipts/agent-probe/<job>.road-frozen.json
receipts/agent-probe/<job>.road-walked.json
receipts/agent-probe/<job>.road-diff.json
receipts/agent-probe/<job>.receipt.json
```

## 5. Verify

```bash
PYTHONPATH=. pytest -q
```

The supported-host test is intentionally skipped unless all host assets and a
live provider credential are explicitly supplied with
`CINDERMOTE_AGENT_PROBE_E2E=1`.
