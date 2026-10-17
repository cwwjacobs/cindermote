"""Historical Incident Gate evidence must retain its original policy binding.

Only schema validation reads the published receipts directly. End-to-end
verifier tests use temporary copies re-signed with a test-only key; they make
no claim about the unpublished original observer key or host execution.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import shlex
import shutil
import sys
from pathlib import Path
from types import ModuleType

import pytest

PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from observer.receipt import sign_receipt, validate_receipt

EVIDENCE_DIR = PROJECT_DIR / "docs" / "audits" / "evidence" / "2026-10-16"
ARCHIVED_POLICY = EVIDENCE_DIR / "hotcell-policy-v1.3.json"
ACTIVE_POLICY = PROJECT_DIR / "policy" / "hotcell-policy.json"
ARCHIVED_SHA256 = "f4b635ec81370ab9892b5f7c1a765b80007265ecea4d7f14d6600e37ad370396"
RUN_IDS = (
    "run-20261016T065642Z-344a69dd",
    "run-20261016T070335Z-7351c694",
)
# This public deterministic key authenticates only temporary test fixtures.
TEST_KEY = bytes(range(32))


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _published_receipts() -> list[Path]:
    return sorted(
        path
        for run_id in RUN_IDS
        for path in (EVIDENCE_DIR / run_id / "receipts").glob("*.json")
    )


def _verifier() -> ModuleType:
    path = PROJECT_DIR / "scripts" / "verify-incident-gate-evidence.py"
    spec = importlib.util.spec_from_file_location("policy_versioning_verifier", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_archived_policy_is_the_exact_published_v1_3_bytes() -> None:
    assert hashlib.sha256(ARCHIVED_POLICY.read_bytes()).hexdigest() == ARCHIVED_SHA256
    entries = [
        line.split(maxsplit=1)
        for line in (EVIDENCE_DIR / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert [entry for entry in entries if entry[1] == ARCHIVED_POLICY.name] == [
        [ARCHIVED_SHA256, ARCHIVED_POLICY.name]
    ]


def test_v1_4_changes_only_version_and_declared_agent_probe_requirement() -> None:
    archived = _json(ARCHIVED_POLICY)
    assert archived["policy_version"] == "cindermote-hotcell-v1.3"
    assert archived["isolation"]["firecracker"]["required_for"] == ["browser-probe"]
    expected = copy.deepcopy(archived)
    expected["policy_version"] = "cindermote-hotcell-v1.4"
    expected["isolation"]["firecracker"]["required_for"].append("agent-probe")
    assert _json(ACTIVE_POLICY) == expected


def test_both_published_verification_commands_select_the_archived_policy() -> None:
    commands: list[list[str]] = []
    pending = ""
    for line in (EVIDENCE_DIR / "README.md").read_text(encoding="utf-8").splitlines():
        pending += line.removesuffix("\\").strip() + " "
        if line.endswith("\\"):
            continue
        if pending.startswith("python3 ") and "verify-incident-gate-evidence.py" in pending:
            commands.append(shlex.split(pending))
        pending = ""

    assert len(commands) == len(RUN_IDS)
    documented_runs: list[str] = []
    for command in commands:
        assert "--expect-all" in command
        policy_arg = command[command.index("--policy") + 1]
        assert (EVIDENCE_DIR / policy_arg).resolve(strict=True) == ARCHIVED_POLICY
        assert (EVIDENCE_DIR / command[1]).resolve(strict=True) == (
            PROJECT_DIR / "scripts" / "verify-incident-gate-evidence.py"
        )
        run_args = [arg for arg in command if arg in RUN_IDS]
        assert len(run_args) == 1
        documented_runs.extend(run_args)
    assert sorted(documented_runs) == sorted(RUN_IDS)


def test_published_incident_gate_evidence_contains_all_twelve_receipts() -> None:
    receipts = _published_receipts()
    assert len(receipts) == 12
    for run_id in RUN_IDS:
        assert len([path for path in receipts if run_id in path.parts]) == 6


@pytest.mark.parametrize("receipt_path", _published_receipts(), ids=lambda path: path.stem)
def test_historical_receipt_accepts_v1_3_and_rejects_active_v1_4(
    receipt_path: Path,
) -> None:
    receipt = _json(receipt_path)
    # Schema acceptance is not HMAC authentication with the private host key.
    validate_receipt(receipt, active_policy=ARCHIVED_POLICY)
    with pytest.raises(ValueError, match="not bound to the active policy"):
        validate_receipt(receipt, active_policy=ACTIVE_POLICY)


@pytest.mark.parametrize("run_id", RUN_IDS)
def test_real_verifier_preserves_historical_policy_binding_on_resigned_copies(
    tmp_path: Path, run_id: str,
) -> None:
    run_root = tmp_path / run_id
    shutil.copytree(EVIDENCE_DIR / run_id, run_root)
    manifest_path = run_root / "cinder-incident-gate.json"
    manifest = _json(manifest_path)
    assert len(manifest["child_receipts"]) == 6
    for entry in manifest["child_receipts"]:
        receipt_path = run_root / entry["path"]
        unsigned = _json(receipt_path)
        unsigned.pop("receipt_signature")
        receipt = dict(unsigned, receipt_signature=sign_receipt(unsigned, TEST_KEY))
        receipt_path.write_text(json.dumps(receipt) + "\n", encoding="utf-8")
        entry["sha256"] = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")
    key_path = tmp_path / "test-only-observer-key"
    key_path.write_bytes(TEST_KEY)
    key_path.chmod(0o600)
    verifier = _verifier()

    accepted = verifier.verify_run(
        run_root, key_path=key_path, policy_path=ARCHIVED_POLICY, expect_all=True,
    )
    assert accepted["verified"] is True, accepted["errors"]
    assert accepted["verified_receipt_count"] == 6

    rejected = verifier.verify_run(
        run_root, key_path=key_path, policy_path=ACTIVE_POLICY, expect_all=True,
    )
    assert rejected["verified"] is False
    assert rejected["verified_receipt_count"] == 0
    assert len(rejected["errors"]) == 6
    assert all("not bound to the active policy" in error for error in rejected["errors"])

    # Confirm that the positive result above actually used signature checking.
    key_path.write_bytes(bytes(reversed(TEST_KEY)))
    wrong_key = verifier.verify_run(
        run_root, key_path=key_path, policy_path=ARCHIVED_POLICY, expect_all=True,
    )
    assert wrong_key["verified"] is False
    assert wrong_key["verified_receipt_count"] == 0
    assert len(wrong_key["errors"]) == 6
    assert all("receipt signature is invalid" in error for error in wrong_key["errors"])
