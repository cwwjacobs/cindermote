from __future__ import annotations

import copy
import json
from pathlib import Path

from cindermote.agent_probe.broker import AgentProbeBroker
from cindermote.agent_probe.contract import ModelConfig, verify_envelope
from cindermote.agent_probe.evidence import GuestEvidenceSealer
from cindermote.agent_probe.firecracker_runtime import AgentProbeRuntimeResult
from cindermote.agent_probe.hpke import generate_key_pair
from cindermote.agent_probe.protocol import digest_bytes
from cindermote.agent_probe.receipt import EXIT_ALLOW, EXIT_INVALID_RECEIPT, derive_exit_code
from cindermote.agent_probe.runner import run_agent_probe


def test_runner_builds_allow_receipt_without_host_plaintext(tmp_path: Path) -> None:
    private, public = generate_key_pair()
    observer = b"o" * 32
    target = tmp_path / "evil-name.skill"
    canary = "HOSTILE_CANARY_DO_NOT_RENDER"
    target.write_text(canary, encoding="utf-8")

    def fake_runtime(**kwargs):
        manifest = kwargs["manifest"]
        road_hash = kwargs["road_frozen_hash"]
        sealer = GuestEvidenceSealer(
            manifest["job_id"], manifest["target"]["target_hash"], road_hash,
            public, manifest["quarantine"]["key_id"], manifest["budgets"]["max_evidence_bytes"],
        )
        sealer.append("initial_prompt", canary.encode())
        sealer.append("guest_status", b"complete", final=True)
        bundle = sealer.finalize()
        broker = AgentProbeBroker(job_id=manifest["job_id"], max_calls=8, revoke=lambda: None)
        broker.evaluate({
            "sequence": 0, "action_code": "submit_task_result", "arg_class": "TASK_SUBMISSION",
            "arg_hash": digest_bytes(b"opaque"),
        })
        evidence_path = Path(kwargs["quarantine_dir"]) / f"{manifest['job_id']}.guest-evidence.json.enc"
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_bytes(json.dumps(bundle, sort_keys=True).encode())
        return AgentProbeRuntimeResult(
            runtime_job_id="mf-web-01234567",
            guest_result={
                "type": "result", "protocol_version": "cindermote.agent-probe-control/v1",
                "nonce": "n", "agent_version": "cindermote-agent-probe-guest/1",
                "job_id": manifest["job_id"], "road_frozen_hash": road_hash,
                "status_code": "COMPLETE", "task_complete": True, "soft_findings": 0,
                "proposal_count": 1,
                "model_metrics": {"requests": 1, "prompt_tokens": 5, "completion_tokens": 2,
                                  "latency_ms": 10, "network_bytes": 100, "retries": 0,
                                  "token_reporting_complete": True},
                "evidence_bundle": bundle,
            },
            broker_events=broker.events,
            egress_events=[],
            egress_telemetry={"complete": True, "network_bytes": 100, "connection_attempts": 1, "event_count": 1},
            runtime={"admitted": True},
            purge={
                "verified_externally": True, "processes_reaped": True, "cgroup_removed": True,
                "network_namespace_removed": True, "ram_jail_removed": True,
                "egress_worker_reaped": True, "credential_revoked": True, "ciphertext_persisted": True,
            },
            evidence_path=str(evidence_path), evidence_sha256="f" * 64, failure_code="NONE",
        )

    result = run_agent_probe(
        target,
        model=ModelConfig("openai-compatible", "model", "https://api.example.com/v1/chat/completions"),
        api_key=bytearray(b"fresh"), observer_key=observer, quarantine_public_key=public,
        quarantine_key_id="a" * 32, quarantine_dir=tmp_path / "quarantine",
        receipt_dir=tmp_path / "receipts", runtime=fake_runtime,
    )
    assert result.exit_code == EXIT_ALLOW
    assert verify_envelope(result.envelope, observer, "cindermote.agent-probe-receipt/v1")
    for path in (result.receipt_path, result.road_frozen_path, result.road_walked_path, result.road_diff_path):
        text = Path(path).read_text(encoding="utf-8")
        assert canary not in text
        assert "evil-name.skill" not in text
    assert canary.encode() not in Path(result.evidence_path).read_bytes()

    tampered = copy.deepcopy(result.envelope)
    tampered["payload"]["gate_decision"] = "DENY"
    assert derive_exit_code(tampered, observer) == EXIT_INVALID_RECEIPT
