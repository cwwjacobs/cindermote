"""Command-line entry point behavior that does not need a sandbox."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

import cli  # noqa: E402
from cindermote import __version__  # noqa: E402


def test_version_is_reported_consistently(capsys: pytest.CaptureFixture[str]) -> None:
    for argv in (["--version"], ["version"]):
        assert cli.main(argv) == 0
        assert capsys.readouterr().out.strip() == f"Cindermote {__version__}"
    assert cli.main([]) == 1
    assert capsys.readouterr().out.startswith(f"Cindermote {__version__}")


def test_version_constant_is_pep440_and_marks_unreleased_trees() -> None:
    assert __version__.startswith("1.0.1")
    assert ".dev" in __version__ or __version__ == "1.0.1"


def test_kernel_laws_reports_what_it_checked(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["kernel-laws"]) == 0
    output = capsys.readouterr().out
    assert "PASS (0 errors; checked" in output
    assert "seams" in output and "capabilities" in output and "components" in output


def test_kernel_laws_fails_when_a_registry_is_broken(capsys: pytest.CaptureFixture[str]) -> None:
    from kernel_laws import VerificationResult

    broken = VerificationResult(valid=False, errors=["SEAM_REGISTRY.md: registry cannot be read (FileNotFoundError)"])
    with mock.patch("kernel_laws.run_kernel_law_checks", return_value=broken):
        assert cli.main(["kernel-laws"]) == 1
    output = capsys.readouterr().out
    assert "FAIL (1 errors)" in output
    assert "SEAM_REGISTRY.md" in output


def _fake_receipt(decision: str = "ALLOW", purge_verified: bool = True) -> dict:
    return {"gate": {"final_decision": decision}, "purge": {"verified_externally": purge_verified}}


@pytest.mark.parametrize("artifact_type", ["python-script", "shell-script", "skill-md", "mcp-server", "tool-definition"])
def test_legacy_detonation_prints_the_deprecation_notice(
    artifact_type: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with mock.patch("cindermote.mote.detonate.detonate", return_value=_fake_receipt()) as detonate:
        assert cli.main(["detonate", "artifact.py", artifact_type]) == 0
    detonate.assert_called_once_with("artifact.py", artifact_type)
    captured = capsys.readouterr()
    assert "DEPRECATED" in captured.err
    assert "agent-probe" in captured.err
    assert json.loads(captured.out)["gate"]["final_decision"] == "ALLOW"


def test_browser_probe_detonation_is_not_called_deprecated(capsys: pytest.CaptureFixture[str]) -> None:
    with mock.patch("cindermote.mote.detonate.detonate", return_value=_fake_receipt()):
        assert cli.main(["detonate", "request.json", "browser-probe"]) == 0
    assert "DEPRECATED" not in capsys.readouterr().err


@pytest.mark.parametrize(
    ("receipt", "expected"),
    [
        (_fake_receipt("ALLOW"), 0),
        (_fake_receipt("DENY"), 2),
        (_fake_receipt("EVALUATION_INCOMPLETE"), 2),
        (_fake_receipt("ALLOW", purge_verified=False), 6),
    ],
)
def test_legacy_exit_codes_never_report_success_without_verified_purge(receipt: dict, expected: int) -> None:
    with mock.patch("cindermote.mote.detonate.detonate", return_value=receipt):
        assert cli.main(["detonate", "artifact.py", "python-script"]) == expected


def test_agent_probe_requires_endpoint_model_and_credential_descriptor(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in (
        "CINDERMOTE_AGENT_PROBE_API_KEY_FD",
        "CINDERMOTE_AGENT_PROBE_ENDPOINT",
        "CINDERMOTE_AGENT_PROBE_MODEL",
    ):
        monkeypatch.delenv(name, raising=False)
    assert cli.main(["detonate", "target.skill", "agent-probe"]) == 3
    assert "agent-probe requires" in capsys.readouterr().err


def test_unknown_subcommand_and_usage_errors(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["frobnicate"]) == 1
    assert "Unknown subcommand" in capsys.readouterr().out
    assert cli.main(["detonate", "only-one-argument"]) == 1
