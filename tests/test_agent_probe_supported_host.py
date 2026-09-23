from __future__ import annotations

import os
from pathlib import Path

import pytest

from cindermote.agent_probe.contract import ModelConfig
from cindermote.agent_probe.runner import run_agent_probe
from cindermote.mote.firecracker_runtime import preflight_firecracker


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
    assert result.envelope["payload"]["execution_status"] == "COMPLETE"
