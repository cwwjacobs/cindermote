"""Tests for Cindermote Kernel Laws Validator (Phase 1)."""

import unittest
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from cindermote.kernel_laws import KernelLawsValidator, run_kernel_law_checks



class TestKernelLaws(unittest.TestCase):
    def setUp(self) -> None:
        self.validator = KernelLawsValidator()

    def test_run_kernel_law_checks_passes(self) -> None:
        result = run_kernel_law_checks()
        self.assertTrue(result.valid, f"Expected valid, got errors: {result.errors}")

    def test_seam_without_owner_fails(self) -> None:
        seams = {
            "version": "v1",
            "seams": [
                {
                    "seam_id": "orphan_seam",
                    "source_zone": "TAINTED_GUEST",
                    "target_zone": "TRUSTED_HOST",
                    "owner": "",
                    "broker": "cindermote-proxy",
                    "instrumented": True
                }
            ]
        }
        res = self.validator.validate_seams(seams)
        self.assertFalse(res.valid)
        self.assertIn("has no assigned owner", res.errors[0])

    def test_unbrokered_guest_to_host_seam_fails(self) -> None:
        seams = {
            "version": "v1",
            "seams": [
                {
                    "seam_id": "direct_seam",
                    "source_zone": "TAINTED_GUEST",
                    "target_zone": "TRUSTED_HOST",
                    "owner": "guest_root",
                    "broker": "",
                    "instrumented": False
                }
            ]
        }
        res = self.validator.validate_seams(seams)
        self.assertFalse(res.valid)
        self.assertIn("Unbrokered guest-to-host seam detected", res.errors[0])

    def test_invalid_capability_disposition_fails(self) -> None:
        caps = {
            "version": "v1",
            "capabilities": [
                {
                    "capability_id": "raw_root_exec",
                    "component_id": "guest",
                    "disposition": "UNKNOWN_DISPOSITION",
                    "broker_required": False
                }
            ]
        }
        res = self.validator.validate_capabilities(caps)
        self.assertFalse(res.valid)

    def test_collapse_cue_lacking_terminal_action_fails(self) -> None:
        cues = {
            "version": "v1",
            "cues": [
                {
                    "cue_id": "overflow",
                    "trigger_condition": "size > 10MB",
                    "terminal_action": "INVALID_ACTION"
                }
            ]
        }
        res = self.validator.validate_collapse_cues(cues)
        self.assertFalse(res.valid)


if __name__ == "__main__":
    unittest.main()
