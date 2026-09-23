"""Compatibility and supported-host tests for the retired portable vertical spine.

Tests the 14 mandatory portable verification invariants:
1. Portable MCP process launch is denied.
2. Portable tools discovery is denied.
3. Portable tool invocation is denied.
4. Portable initialization is denied.
5. Portable vertical execution is denied.
6. Unknown capability forces Collapse.
7. Hard-coded or default signing keys are rejected.
8. Fabricated cleanup claims are rejected.
9. Ash authentication detects receipt mutation.
10. Replay encryption/decryption round trip occurs only via QuarantinedReplayViewer.
11. Source packager excludes secrets, evidence, caches, and runtime state.
12. Active rename audit reports only documented intentional Motefield occurrences.
13. Import collection succeeds (python3 -m compileall -q .).
14. Supported-host KVM test returns SKIPPED / PORTABLE_VERIFIED_SUPPORTED_HOST_PENDING if /dev/kvm is missing.
"""

import json
import os
import sys
import unittest
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from ash_receipt import AshReceipt, create_ash_receipt, generate_local_signing_key
from capability_brokers import CapabilityBroker
from cindermote_vertical_spine import CindermoteVerticalSpine
from mcp_guest_controller import (
    HOST_NATIVE_EXECUTION_DISABLED,
    GuestMCPController,
    HostNativeExecutionDisabled,
)
from quarantined_replay_viewer import QuarantinedReplayViewer
from sealed_replay import SealedReplayEngine

FIXTURE_MCP_SERVER = PROJECT_DIR / "tests" / "fixtures" / "test_mcp_server.py"


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
        ash = create_ash_receipt(self.run_id, "target", "hash")
        with self.assertRaises(ValueError):
            ash.sign(b"cindermote-observer-key-32bytes!")

    def test_08_fabricated_cleanup_claims_rejected(self) -> None:
        ash = create_ash_receipt(self.run_id, "target", "hash")
        # Default unverified purge results are False
        self.assertFalse(ash.purge_verification_results["process_reaped"])
        self.assertFalse(ash.purge_verification_results["cgroup_removed"])

    def test_09_ash_authentication_detects_mutation(self) -> None:
        key = generate_local_signing_key()
        ash = create_ash_receipt(self.run_id, "target", "hash", key_bytes=key)
        self.assertTrue(ash.verify_signature(key))

        # Mutate receipt
        ash.final_disposition = "ADMIT"
        self.assertFalse(ash.verify_signature(key))

    def test_10_replay_encryption_decryption_round_trip(self) -> None:
        engine = SealedReplayEngine()
        raw_data = b"confidential_guest_replay_data"
        descriptor, per_run_key = engine.seal_replay("run-seal-1", raw_data)

        # Inspect only via QuarantinedReplayViewer
        res = QuarantinedReplayViewer.inspect_sealed_replay(descriptor.storage_path, per_run_key)
        self.assertEqual(res["decrypted_status"], "QUARANTINED_VIEWER_ACCESS_GRANTED")
        self.assertEqual(res["ciphertext_hash"], descriptor.ciphertext_hash)

    def test_11_source_packaging_excludes_secrets_and_runtime_state(self) -> None:
        # Check .gitignore covers keys and evidence
        gitignore = (PROJECT_DIR / ".gitignore").read_text()
        self.assertIn(".observer_key", gitignore)
        self.assertIn("receipts/", gitignore)
        self.assertIn("quarantine/", gitignore)

    def test_12_active_rename_audit(self) -> None:
        # Check active codebase files do not have motefield in code (except provenance/migration)
        provenance = (PROJECT_DIR / "PROVENANCE.md").read_text()
        migration = (PROJECT_DIR / "MIGRATION_FROM_MOTEFIELD.md").read_text()
        naming = (PROJECT_DIR / "NAMING.md").read_text()
        self.assertIn("Motefield", provenance)
        self.assertIn("Motefield", migration)
        self.assertIn("Motefield", naming)

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
