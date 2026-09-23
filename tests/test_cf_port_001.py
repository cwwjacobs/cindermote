"""Focused regressions for CF-PORT-001 host-native execution containment."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

import mote.detonate as detonate_module
from cli import main as cli_main
from cindermote_api import CindermoteService
from cindermote_vertical_spine import CindermoteVerticalSpine
from mcp_guest_controller import (
    HOST_NATIVE_EXECUTION_DISABLED,
    GuestMCPController,
    HostNativeExecutionDisabled,
)
from mote.browser_contract import make_probe_request
from mote.firecracker_runtime import (
    FirecrackerUnavailable,
    PreflightCheck,
    PreflightReport,
)


def test_a_controller_cannot_launch_any_host_process() -> None:
    controller = GuestMCPController(
        "cf-port-001-controller",
        [sys.executable, "-c", "raise SystemExit('must not execute')"],
    )

    with (
        mock.patch.object(subprocess, "Popen") as popen,
        mock.patch.object(subprocess, "run") as run,
        mock.patch.object(subprocess, "call") as call,
        mock.patch.object(os, "system") as system,
        mock.patch.object(os, "popen") as os_popen,
        mock.patch.object(os, "execv") as execv,
        mock.patch.object(os, "execve") as execve,
        pytest.raises(HostNativeExecutionDisabled) as raised,
    ):
        controller.start_target()

    assert raised.value.reason_code == HOST_NATIVE_EXECUTION_DISABLED
    assert raised.value.execution_started is False
    for launch in (popen, run, call, system, os_popen, execv, execve):
        launch.assert_not_called()


def test_b_vertical_spine_denies_before_sentinel_execution(tmp_path: Path) -> None:
    sentinel = tmp_path / "portable-target-executed"
    command = [
        sys.executable,
        "-c",
        f"from pathlib import Path; Path({str(sentinel)!r}).write_text('executed')",
    ]
    spine = CindermoteVerticalSpine("cf-port-001-spine", command)

    with pytest.raises(HostNativeExecutionDisabled) as raised:
        spine.execute_vertical_run()

    assert raised.value.reason_code == HOST_NATIVE_EXECUTION_DISABLED
    assert raised.value.execution_started is False
    assert not sentinel.exists()


def test_c_api_denies_without_false_execution_attestation() -> None:
    result = CindermoteService().create_detonation(
        {
            "target": {"id": "untrusted", "package_uri": "file:///tmp/target"},
            "raw_manifest": {"tools": [{"name": "host_command"}]},
        }
    )

    assert result["status"] == "DENIED"
    assert result["disposition"] == "DENY"
    assert result["reason_code"] == HOST_NATIVE_EXECUTION_DISABLED
    assert result["execution_started"] is False
    assert not {
        "ash_receipt",
        "sealed_replay",
        "receipt",
        "replay",
        "purge",
        "encrypted",
        "verified",
    }.intersection(result)
    assert not {"ALLOW", "ADMIT", "NORMAL", "COMPLETED", "SUCCESS"}.intersection(
        value for value in result.values() if isinstance(value, str)
    )


def test_c_cli_propagates_portable_denial_as_failure(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = cli_main(["spine", "detonation"])
    result = json.loads(capsys.readouterr().out)

    assert exit_code == 3
    assert result["status"] == "DENIED"
    assert result["reason_code"] == HOST_NATIVE_EXECUTION_DISABLED
    assert result["execution_started"] is False
    assert "ash_receipt" not in result
    assert "sealed_replay" not in result


def test_d_firecracker_admission_failure_never_falls_back_to_portable() -> None:
    report = PreflightReport(
        ready=False,
        profile="browser",
        checks=(PreflightCheck("kvm", False, True, "unavailable in unit test"),),
    )

    with (
        mock.patch.object(
            detonate_module,
            "run_browser_probe",
            side_effect=FirecrackerUnavailable(report),
        ) as firecracker,
        mock.patch.object(
            GuestMCPController,
            "start_target",
            side_effect=AssertionError("portable fallback attempted"),
        ) as portable,
        pytest.raises(FirecrackerUnavailable),
    ):
        detonate_module.detonate_browser_probe(
            make_probe_request("https://example.org/")
        )

    firecracker.assert_called_once()
    portable.assert_not_called()


def test_e_canonical_firecracker_browser_route_remains_selectable(
    tmp_path: Path,
) -> None:
    request_path = tmp_path / "browser-probe.json"
    request_path.write_text(json.dumps({"contract_version": "mock"}), encoding="utf-8")
    routed = {"route": "canonical-firecracker-browser-probe"}

    with mock.patch.object(
        detonate_module, "detonate_browser_probe", return_value=routed
    ) as firecracker_route:
        result = detonate_module.detonate(request_path, "browser-probe")

    assert result is routed
    firecracker_route.assert_called_once()
