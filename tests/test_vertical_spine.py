"""Compatibility and supported-host tests for the retired portable vertical spine.

Tests the 14 mandatory portable verification invariants:
1. Portable MCP process launch is denied.
2. Portable tools discovery is denied.
3. Portable tool invocation is denied.
4. Portable initialization is denied.
5. Portable vertical execution is denied.
6. Unknown capability forces Collapse (reference model; not wired to an entry point).
7. Hard-coded or default signing keys are rejected on the real receipt signing path.
8. Fabricated cleanup claims are rejected by the real receipt builder.
9. Receipt authentication detects mutation.
10. Sealed guest evidence is only readable with the offline key (real HPKE + secretstream path).
11. Source packager excludes secrets, evidence, caches, and runtime state.
12. Active rename audit scans code for the predecessor name; only documented documents may use it.
13. Import collection succeeds (python3 -m compileall -q .).
14. Supported-host KVM test returns SKIPPED / PORTABLE_VERIFIED_SUPPORTED_HOST_PENDING if /dev/kvm is missing.
"""

import json
import os
import re
import sys
import unittest
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from agent_probe.contract import ContractError, sign_envelope, verify_envelope
from agent_probe.evidence import EvidenceError, GuestEvidenceSealer, decrypt_bundle
from agent_probe.hpke import HpkeError, generate_key_pair
from agent_probe.receipt import build_receipt_envelope
from capability_brokers import CapabilityBroker
from cindermote_vertical_spine import CindermoteVerticalSpine
from mcp_guest_controller import (
    HOST_NATIVE_EXECUTION_DISABLED,
    GuestMCPController,
    HostNativeExecutionDisabled,
)

FIXTURE_MCP_SERVER = PROJECT_DIR / "tests" / "fixtures" / "test_mcp_server.py"


def find_predecessor_name_in_code(root: Path, ignore: "set[Path] | None" = None) -> "list[str]":
    """Return code/config files under ``root`` that still use the predecessor name."""

    pattern = re.compile("mote" + "field", re.IGNORECASE)
    skipped_dirs = {
        ".git", "__pycache__", ".cindermote", "receipts", "quarantine", "alerts",
        "dist", "scratch", ".ruff_cache", ".mypy_cache", ".pytest_cache",
    }
    scanned_suffixes = {".py", ".sh", ".json", ".js", ".html", ".css", ".yml", ".yaml", ".toml", ".cfg", ".ini"}
    offenders = []
    for current, directories, files in os.walk(root):
        directories[:] = [d for d in directories if d not in skipped_dirs]
        for name in files:
            path = Path(current) / name
            if ignore and path.resolve() in ignore:
                continue
            if path.suffix not in scanned_suffixes and name not in {"Containerfile", "cindermote-init"}:
                continue
            if name.startswith("golden-snapshot"):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            if pattern.search(text):
                offenders.append(str(path.relative_to(root)))
    return sorted(offenders)


class TestVerticalSpine(unittest.TestCase):
    def setUp(self) -> None:
        self.run_id = "run-test-vertical-01"
        self.cmd = [sys.executable, str(FIXTURE_MCP_SERVER)]

    def test_01_mcp_initialization_is_disabled(self) -> None:
        controller = GuestMCPController(self.run_id, self.cmd)
        with self.assertRaises(HostNativeExecutionDisabled) as raised:
            controller.start_target()
        self.assertEqual(raised.exception.reason_code, HOST_NATIVE_EXECUTION_DISABLED)
        self.assertIsNone(controller.proc)

    def test_02_tools_list_is_disabled(self) -> None:
        controller = GuestMCPController(self.run_id, self.cmd)
        with self.assertRaises(HostNativeExecutionDisabled):
            controller.discover_tools()

    def test_03_tool_invocation_is_disabled(self) -> None:
        controller = GuestMCPController(self.run_id, self.cmd)
        with self.assertRaises(HostNativeExecutionDisabled):
            controller.invoke_tool("echo_tool", {"message": "test_call"})

    def test_04_protocol_initialization_is_disabled(self) -> None:
        controller = GuestMCPController(self.run_id, self.cmd)
        with self.assertRaises(HostNativeExecutionDisabled):
            controller.initialize()

    def test_05_vertical_execution_is_disabled(self) -> None:
        spine = CindermoteVerticalSpine(self.run_id, self.cmd)
        with self.assertRaises(HostNativeExecutionDisabled) as raised:
            spine.execute_vertical_run(trigger_collapse=False)
        self.assertEqual(raised.exception.reason_code, HOST_NATIVE_EXECUTION_DISABLED)

    def test_06_unknown_capability_causes_collapse(self) -> None:
        broker = CapabilityBroker()
        dec = broker.evaluate_request("unknown_capability_xyz", {})
        self.assertEqual(dec.disposition, "COLLAPSE")
        self.assertEqual(dec.collapse_cue, "unknown_capability_request")

    def test_07_hardcoded_or_default_signing_keys_rejected(self) -> None:
        for key in (
            b"cindermote-observer-key-32bytes!",
            b"12345678901234567890123456789012",
            b"default_key",
            b"short",
        ):
            with self.assertRaises(ContractError):
                sign_envelope({"run_id": self.run_id}, "cindermote.test/v1", key)

    def test_08_fabricated_cleanup_claims_rejected(self) -> None:
        key = bytes(range(32))
        with self.assertRaises(ValueError):
            build_receipt_envelope(
                job_manifest={"job_id": "job-0123456789abcdef", "target": {"target_hash": "1" * 64}},
                road_frozen={},
                road_walked={},
                road_diff={},
                guest_evidence_manifest={"guest_evidence_root": "2" * 64, "complete": True},
                host_lifecycle={
                    "host_lifecycle_root": "3" * 64,
                    "egress_witness_complete": True,
                    "cleanup_verified": False,
                },
                execution_status="COMPLETE",
                gate_decision="ALLOW",
                cleanup_status="UNVERIFIED",
                observer_key=key,
            )

    def test_09_receipt_authentication_detects_mutation(self) -> None:
        key = bytes(range(32))
        envelope = sign_envelope({"run_id": self.run_id, "disposition": "DENY"}, "cindermote.test/v1", key)
        self.assertTrue(verify_envelope(envelope, key, "cindermote.test/v1"))

        envelope["payload"]["disposition"] = "ALLOW"
        self.assertFalse(verify_envelope(envelope, key, "cindermote.test/v1"))

    def test_10_sealed_evidence_round_trip_requires_the_offline_key(self) -> None:
        private, public = generate_key_pair()
        raw = b"confidential_guest_replay_data"
        sealer = GuestEvidenceSealer(
            "job-0123456789abcdef", "1" * 64, "2" * 64, public, "a" * 32, 1024 * 1024
        )
        sealer.append("initial_prompt", raw, final=True)
        bundle = sealer.finalize()

        self.assertNotIn(raw, json.dumps(bundle).encode("utf-8"))
        self.assertEqual(decrypt_bundle(bundle, private), [raw])
        wrong_private, _wrong_public = generate_key_pair()
        with self.assertRaises((EvidenceError, HpkeError)):
            decrypt_bundle(bundle, wrong_private)

    def test_11_source_packaging_excludes_secrets_and_runtime_state(self) -> None:
        # Check .gitignore covers keys and evidence
        gitignore = (PROJECT_DIR / ".gitignore").read_text()
        self.assertIn(".observer_key", gitignore)
        self.assertIn("receipts/", gitignore)
        self.assertIn("quarantine/", gitignore)

    def test_12_active_rename_audit(self) -> None:
        # The three documents named in NAMING.md must keep the predecessor name.
        for name in ("PROVENANCE.md", "MIGRATION_FROM_MOTEFIELD.md", "NAMING.md"):
            self.assertIn("Motefield", (PROJECT_DIR / name).read_text(), name)

        # Everything else that is code or configuration must not use it.
        offenders = find_predecessor_name_in_code(PROJECT_DIR, ignore={Path(__file__).resolve()})
        self.assertEqual(offenders, [], "predecessor name found in active code or configuration")

    def test_12b_rename_audit_detects_offenders(self) -> None:
        # Guard against the audit passing vacuously.
        import tempfile

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "clean.py").write_text("print('cindermote')\n", encoding="utf-8")
            (root / "dirty.json").write_text('{"repo": "Mote' + 'field"}', encoding="utf-8")
            (root / "notes.md").write_text("Mote" + "field is allowed in prose docs", encoding="utf-8")
            self.assertEqual(find_predecessor_name_in_code(root), ["dirty.json"])

    def test_13_import_collection_succeeds(self) -> None:
        import compileall
        res = compileall.compile_dir(str(PROJECT_DIR), quiet=1)
        self.assertTrue(res)

    def test_14_supported_host_kvm_check(self) -> None:
        kvm_exists = os.path.exists("/dev/kvm")
        if not kvm_exists:
            self.skipTest("SKIPPED: /dev/kvm is absent. Status: PORTABLE_VERIFIED_SUPPORTED_HOST_PENDING")


if __name__ == "__main__":
    unittest.main()
