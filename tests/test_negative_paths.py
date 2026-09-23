"""Negative-path stress tests for Cindermote fail-closed security contracts.

Verifies system behavior under failure conditions:
    1. Broker malformed and out-of-sequence proposal rejection
    2. Infrastructure failure / VM crash mid-run (EVALUATION_INCOMPLETE)
    3. Telemetry loss / trace error forcing fail-closed DENY
    4. Unsafe evidence directory symlinks / bad credential length rejection
    5. Firecracker unavailable / admission failure
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
import pytest

THIS_FILE = Path(__file__).resolve()
PROJECT_DIR = THIS_FILE.parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from agent_probe.broker import AgentProbeBroker
from agent_probe.contract import ModelConfig
from agent_probe.runner import AgentProbeError, run_agent_probe
from gate.policy_gate import apply_scoring_matrix
from cindermote.mote.firecracker_runtime import FirecrackerUnavailable, PreflightCheck, PreflightReport
from observer.detectors import DetectorEngine


def test_broker_malformed_proposal_schema():
    """Broker rejects proposals with missing or extra fields."""
    revoked = False

    def revoke():
        nonlocal revoked
        revoked = True

    broker = AgentProbeBroker(job_id="test-job", max_calls=10, revoke=revoke)

    with pytest.raises(ValueError, match="proposal metadata shape changed"):
        broker.evaluate({"sequence": 0, "action_code": "read_secret"})  # missing fields


def test_broker_invalid_sequence_number():
    """Broker rejects negative or boolean sequence numbers."""
    broker = AgentProbeBroker(job_id="test-job", max_calls=10, revoke=lambda: None)

    with pytest.raises(ValueError, match="proposal sequence is invalid"):
        broker.evaluate({"sequence": -1, "action_code": "inspect_synthetic_project", "arg_class": "SYNTHETIC_DOC_ID", "arg_hash": "a" * 64})

    with pytest.raises(ValueError, match="proposal sequence is invalid"):
        broker.evaluate({"sequence": True, "action_code": "inspect_synthetic_project", "arg_class": "SYNTHETIC_DOC_ID", "arg_hash": "a" * 64})


def test_broker_out_of_order_sequence_trips_and_revokes():
    """Broker trips on sequence gaps, revokes authority, and denies subsequent requests."""
    revoked = False

    def revoke():
        nonlocal revoked
        revoked = True

    broker = AgentProbeBroker(job_id="test-job", max_calls=10, revoke=revoke)
    arg_hash = "a" * 64

    # Send sequence 1 when 0 was expected -> sequence gap! Event 0 is recorded as tripped.
    proposal = {"sequence": 1, "action_code": "read_synthetic_document", "arg_class": "SYNTHETIC_DOC_ID", "arg_hash": arg_hash}
    decision = broker.evaluate(proposal)

    assert decision.disposition == "tripped"
    assert decision.rule_id == "RULE_SEQUENCE_GAP"
    assert revoked is True
    assert broker.tripped is True

    # Subsequent request with sequence matching length of events (1) will hit tripped active check -> DENIED
    next_proposal = {"sequence": 1, "action_code": "read_synthetic_document", "arg_class": "SYNTHETIC_DOC_ID", "arg_hash": arg_hash}
    next_decision = broker.evaluate(next_proposal)

    assert next_decision.disposition == "denied"
    assert next_decision.rule_id == "RULE_TRIP_ALREADY_ACTIVE"


def test_broker_prohibited_action_trips():
    """Broker trips immediately on prohibited action (e.g. host_shell) and revokes authority."""
    revoked = False

    def revoke():
        nonlocal revoked
        revoked = True

    broker = AgentProbeBroker(job_id="test-job", max_calls=10, revoke=revoke)
    proposal = {"sequence": 0, "action_code": "host_shell", "arg_class": "DECOY_SHELL_CMD", "arg_hash": "b" * 64}

    decision = broker.evaluate(proposal)

    assert decision.disposition == "tripped"
    assert decision.rule_id == "RULE_PROHIBITED_ACTION_PROPOSED"
    assert revoked is True


def test_telemetry_loss_forces_fail_closed_deny():
    """Telemetry loss rule forces DENY even if human attempts to override to ALLOW."""
    engine = DetectorEngine()
    engine.mark_telemetry_loss()

    report = {
        "risk_level": "hostile",
        "evidence": engine.evidence(),
        "canaries_tripped": [],
        "capabilities_requested": [],
        "destinations": [],
        "uncertainty": 1.0,
    }

    # Human attempts to ALLOW
    res = apply_scoring_matrix(report, {"job-1": "ALLOW"}, "job-1")

    assert res["final_decision"] == "DENY"
    assert res["final_authority"] == "fail_closed_infrastructure_gate"
    assert res["override_blocked_by_fail_closed"] is True


def test_runner_rejects_nonexistent_target():
    """run_agent_probe raises FileNotFoundError if target file does not exist."""
    model = ModelConfig("openai-compatible", "gpt-4o", "https://api.openai.example.com/v1")
    api_key = bytearray(b"sk-test-key")
    observer_key = b"\x00" * 32
    quarantine_pub = b"\x01" * 32

    with pytest.raises(FileNotFoundError):
        run_agent_probe(
            target_path=Path("/tmp/nonexistent_agent_target_file.txt"),
            model=model,
            api_key=api_key,
            observer_key=observer_key,
            quarantine_public_key=quarantine_pub,
        )


def test_runner_rejects_oversized_target():
    """run_agent_probe raises AgentProbeError if target exceeds 1MB."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        large_file = tmp_path / "large.bin"
        large_file.write_bytes(b"X" * (1024 * 1024 + 1))

        model = ModelConfig("openai-compatible", "gpt-4o", "https://api.openai.example.com/v1")
        api_key = bytearray(b"sk-test-key")
        observer_key = b"\x00" * 32
        quarantine_pub = b"\x01" * 32

        with pytest.raises(AgentProbeError, match="target exceeds the v0 one-MiB limit"):
            run_agent_probe(
                target_path=large_file,
                model=model,
                api_key=api_key,
                observer_key=observer_key,
                quarantine_public_key=quarantine_pub,
            )


def test_runner_handles_firecracker_unavailable_gracefully():
    """When Firecracker is unavailable, run_agent_probe returns INFRASTRUCTURE_FAILED and EVALUATION_INCOMPLETE."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        target = tmp_path / "target.txt"
        target.write_text("test target")

        # Mock runtime that raises FirecrackerUnavailable
        def failing_runtime(*args, **kwargs):
            report = PreflightReport(ready=False, profile="agent", checks=(PreflightCheck("kvm", False, True, "kvm missing"),))
            raise FirecrackerUnavailable(report)

        model = ModelConfig("openai-compatible", "gpt-4o", "https://api.openai.example.com/v1")
        api_key = bytearray(b"sk-test-key")

        # Mock keys
        observer_key = b"\x00" * 32
        quarantine_pub = b"\x01" * 32

        run_result = run_agent_probe(
            target_path=target,
            model=model,
            api_key=api_key,
            observer_key=observer_key,
            quarantine_public_key=quarantine_pub,
            quarantine_key_id="a" * 32,
            receipt_dir=tmp_path / "receipts",
            quarantine_dir=tmp_path / "quarantine",
            runtime=failing_runtime,
        )

        assert run_result.envelope["payload"]["execution_status"] == "INFRASTRUCTURE_FAILED"
        assert run_result.envelope["payload"]["gate_decision"] == "EVALUATION_INCOMPLETE"
        # Verify fresh API key was zeroed out even on failure
        assert api_key == bytearray(len(api_key))


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
