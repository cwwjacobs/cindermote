from __future__ import annotations

import copy
import errno
import json
from pathlib import Path

from cindermote.agent_probe.broker import AgentProbeBroker
from cindermote.agent_probe.contract import ModelConfig, verify_envelope
from cindermote.agent_probe.evidence import GuestEvidenceSealer
from cindermote.agent_probe.firecracker_runtime import AgentProbeRuntimeResult
from cindermote.agent_probe.hpke import generate_key_pair
from cindermote.agent_probe.protocol import digest_bytes
from cindermote.agent_probe.receipt import (
    EXIT_ALLOW,
    EXIT_CLEANUP_FAILURE,
    EXIT_INVALID_RECEIPT,
    derive_exit_code,
)
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


def _run_with_failing_runtime(tmp_path: Path, failure: BaseException):
    observer = b"o" * 32
    target = tmp_path / "evil-name.skill"
    marker = "HOST_PATH_MARKER_DO_NOT_LEAK"
    target.write_text("payload", encoding="utf-8")

    def failing_runtime(**kwargs):
        assert any(kwargs["api_key"]), "API key must still be live inside the runtime call"
        raise failure

    api_key = bytearray(b"fresh-secret")
    result = run_agent_probe(
        target,
        model=ModelConfig("openai-compatible", "model", "https://api.example.com/v1/chat/completions"),
        api_key=api_key,
        observer_key=observer,
        quarantine_public_key=b"p" * 32,
        quarantine_key_id="a" * 32,
        quarantine_dir=tmp_path / "quarantine",
        receipt_dir=tmp_path / "receipts",
        runtime=failing_runtime,
    )
    return result, api_key, observer, marker


def _assert_signed_incomplete_run(result, api_key: bytearray, observer: bytes, marker: str) -> None:
    # The key buffer is zeroed even though the runtime raised.
    assert api_key == bytearray(len(api_key))
    # A signed failure receipt and the supporting road artifacts are persisted.
    for path in (
        result.receipt_path,
        result.road_frozen_path,
        result.road_walked_path,
        result.road_diff_path,
    ):
        assert Path(path).is_file(), path
    assert verify_envelope(result.envelope, observer, "cindermote.agent-probe-receipt/v1")
    payload = result.envelope["payload"]
    assert payload["execution_status"] == "INFRASTRUCTURE_FAILED"
    assert payload["gate_decision"] == "EVALUATION_INCOMPLETE"
    assert result.exit_code == derive_exit_code(result.envelope, observer)
    assert result.exit_code == EXIT_CLEANUP_FAILURE
    assert result.exit_code != EXIT_ALLOW
    # Bounded failure metadata must not smuggle host paths or target names.
    for path in (result.receipt_path, result.road_frozen_path, result.road_walked_path, result.road_diff_path):
        text = Path(path).read_text(encoding="utf-8")
        assert marker not in text
        assert "evil-name.skill" not in text


def test_runtime_oserror_zeroes_key_and_persists_signed_failure_receipt(tmp_path: Path) -> None:
    result, api_key, observer, marker = _run_with_failing_runtime(
        tmp_path, OSError(errno.EIO, "device vanished at /host/HOST_PATH_MARKER_DO_NOT_LEAK")
    )
    _assert_signed_incomplete_run(result, api_key, observer, marker)
    road_walked = json.loads(Path(result.road_walked_path).read_text(encoding="utf-8"))
    assert road_walked["runtime_failure_code"] == "RUNTIME_OSERROR"
    assert road_walked["runtime_failure"] == {"exception": "OSError", "errno": errno.EIO}


def test_unexpected_runtime_exception_zeroes_key_and_persists_signed_failure_receipt(tmp_path: Path) -> None:
    result, api_key, observer, marker = _run_with_failing_runtime(
        tmp_path, RuntimeError("boom referencing /host/HOST_PATH_MARKER_DO_NOT_LEAK")
    )
    _assert_signed_incomplete_run(result, api_key, observer, marker)
    road_walked = json.loads(Path(result.road_walked_path).read_text(encoding="utf-8"))
    assert road_walked["runtime_failure_code"] == "RUNTIME_UNEXPECTED_ERROR"
    assert road_walked["runtime_failure"] == {"exception": "RuntimeError", "errno": None}


def test_read_exact_key_accepts_raw_key_ending_in_whitespace(tmp_path: Path) -> None:
    from cindermote.agent_probe.runner import AgentProbeError, _read_exact_key

    key_path = tmp_path / "key"
    raw_key = b"k" * 31 + b" "
    key_path.write_bytes(raw_key)
    assert _read_exact_key(key_path, name="observer signing key", lengths={32, 48, 64}) == raw_key

    key_path.write_bytes(b"n" * 32 + b"\n")
    assert _read_exact_key(key_path, name="observer signing key", lengths={32, 48, 64}) == b"n" * 32

    key_path.write_bytes(b"ab" * 48 + b"\n")
    assert _read_exact_key(key_path, name="observer signing key", lengths={48}) == bytes.fromhex("ab" * 48)

    key_path.write_bytes(b"short")
    try:
        _read_exact_key(key_path, name="observer signing key", lengths={32, 48, 64})
    except AgentProbeError:
        pass
    else:
        raise AssertionError("invalid-length key must be rejected")
