from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from cindermote.agent_probe.contract import ModelConfig, verify_envelope
from cindermote.agent_probe.evidence import validate_bundle
from cindermote.agent_probe.receipt import derive_exit_code
from cindermote.agent_probe.runner import run_agent_probe
from cindermote.mote.firecracker_runtime import (
    DEFAULT_CGROUP_ROOT,
    DEFAULT_RUNTIME_ROOT,
    _owned_stale_job_tokens,
    preflight_firecracker,
)


def test_real_firecracker_agent_probe_on_explicit_supported_host(tmp_path: Path) -> None:
    report = preflight_firecracker(profile="agent-probe")
    endpoint = os.environ.get("CINDERMOTE_AGENT_PROBE_E2E_ENDPOINT")
    model = os.environ.get("CINDERMOTE_AGENT_PROBE_E2E_MODEL")
    credential = os.environ.get("CINDERMOTE_AGENT_PROBE_E2E_KEY")
    if not report.ready or not endpoint or not model or not credential or os.environ.get("CINDERMOTE_AGENT_PROBE_E2E") != "1":
        pytest.skip("requires explicit supported-host KVM assets and live provider credential")
    target = tmp_path / "benign.skill"
    target.write_text("Use only declared synthetic tools and complete the task.", encoding="utf-8")
    result = run_agent_probe(
        target,
        model=ModelConfig("openai-compatible", model, endpoint),
        api_key=bytearray(credential.encode()),
    )
    observer_key = (Path(__file__).resolve().parents[1] / ".observer_key").read_bytes()
    payload = result.envelope["payload"]
    assert verify_envelope(result.envelope, observer_key, "cindermote.agent-probe-receipt/v1")
    assert json.loads(Path(result.receipt_path).read_text(encoding="ascii")) == result.envelope
    assert result.exit_code == derive_exit_code(result.envelope, observer_key)
    road_walked = json.loads(Path(result.road_walked_path).read_text(encoding="ascii"))
    print(
        json.dumps(
            {
                "job_id": result.job_id,
                "execution_status": payload["execution_status"],
                "runtime_failure_code": road_walked["runtime_failure_code"],
                "runtime_failure": road_walked.get("runtime_failure"),
                "receipt_path": result.receipt_path,
                "road_walked_path": result.road_walked_path,
            },
            sort_keys=True,
        )
    )
    assert payload["execution_status"] == "COMPLETE"
    assert payload["cleanup_status"] == "VERIFIED"
    assert payload["witnesses"] == {
        "guest_complete": True,
        "egress_complete": True,
        "cleanup_complete": True,
    }
    assert result.evidence_path is not None
    evidence_bytes = Path(result.evidence_path).read_bytes()
    bundle = json.loads(evidence_bytes)
    manifest = validate_bundle(bundle)["manifest"]
    assert manifest["job_id"] == result.job_id
    assert manifest["guest_evidence_root"] == payload["guest_evidence_root"]
    assert not _owned_stale_job_tokens(DEFAULT_RUNTIME_ROOT, DEFAULT_CGROUP_ROOT)
    receipt_bytes = Path(result.receipt_path).read_bytes()
    print(
        json.dumps(
            {
                "job_id": result.job_id,
                "execution_status": payload["execution_status"],
                "gate_decision": payload["gate_decision"],
                "cleanup_status": payload["cleanup_status"],
                "witnesses": payload["witnesses"],
                "receipt_path": result.receipt_path,
                "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
                "evidence_path": result.evidence_path,
                "evidence_sha256": hashlib.sha256(evidence_bytes).hexdigest(),
            },
            sort_keys=True,
        )
    )
