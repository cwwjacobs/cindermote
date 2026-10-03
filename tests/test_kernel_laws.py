"""Tests for the Kernel Laws registry validator."""

import shutil
import tempfile
import unittest
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from cindermote.kernel_laws import (
    KernelLawsValidator,
    parse_markdown_tables,
    run_kernel_law_checks,
)

DOCS_DIR = PROJECT_DIR / "docs"


class TestKernelLaws(unittest.TestCase):
    def setUp(self) -> None:
        self.validator = KernelLawsValidator()

    def test_run_kernel_law_checks_passes_on_the_repository_registries(self) -> None:
        result = run_kernel_law_checks()
        self.assertTrue(result.valid, f"Expected valid, got errors: {result.errors}")
        # It must have actually read the registries, not passed on nothing.
        self.assertGreaterEqual(result.summary["seams"], 5)
        self.assertGreaterEqual(result.summary["capabilities"], 12)
        self.assertGreaterEqual(result.summary["cues"], 8)
        self.assertGreaterEqual(result.summary["components"], 10)

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


class TestRegistryChecksCanFail(unittest.TestCase):
    """The check reads docs/; a broken or missing registry must fail, never pass."""

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.docs = Path(self._temporary.name) / "docs"
        shutil.copytree(DOCS_DIR, self.docs)

    def _edit(self, name: str, old: str, new: str) -> None:
        path = self.docs / name
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text, f"{name} no longer contains the fixture text")
        path.write_text(text.replace(old, new), encoding="utf-8")

    def _errors(self) -> str:
        result = run_kernel_law_checks(self.docs)
        self.assertFalse(result.valid)
        return "\n".join(result.errors)

    def test_copied_registries_pass_unmodified(self) -> None:
        self.assertTrue(run_kernel_law_checks(self.docs).valid)

    def test_missing_registry_fails(self) -> None:
        (self.docs / "SEAM_REGISTRY.md").unlink()
        self.assertIn("SEAM_REGISTRY.md: registry cannot be read", self._errors())

    def test_registry_without_a_table_fails(self) -> None:
        (self.docs / "COLLAPSE_CUES.md").write_text("# Collapse cues\n\nNothing here.\n", encoding="utf-8")
        self.assertIn("COLLAPSE_CUES.md: no table", self._errors())

    def test_unbrokered_guest_to_host_seam_fails(self) -> None:
        self._edit("SEAM_REGISTRY.md", "| `AgentProbeBroker` |", "| None (Direct) |")
        self.assertIn("Unbrokered guest-to-host seam detected: guest_proposal_channel", self._errors())

    def test_uninstrumented_seam_fails(self) -> None:
        self._edit("SEAM_REGISTRY.md", "| `FirecrackerRuntime` | None (Direct) | Yes |", "| `FirecrackerRuntime` | None (Direct) | No |")
        self.assertIn("host_collapse_signal is not instrumented", self._errors())

    def test_unknown_trust_zone_fails(self) -> None:
        self._edit("SEAM_REGISTRY.md", "| QUARANTINE | TRUSTED_HOST |", "| LIMBO | TRUSTED_HOST |")
        self.assertIn("unknown source_zone: LIMBO", self._errors())

    def test_capability_without_broker_violates_law_2(self) -> None:
        self._edit("CAPABILITY_MANIFEST.md", "| `guest_network` | `GuestMCPController` | Yes |", "| `guest_network` | `GuestMCPController` | No |")
        self.assertIn("Law 2: capability guest_network does not require a broker", self._errors())

    def test_unknown_capability_must_collapse_law_3(self) -> None:
        self._edit("CAPABILITY_MANIFEST.md", "| *unknown capability* | *any* | Yes | COLLAPSE |", "| *unknown capability* | *any* | Yes | ALLOW |")
        self.assertIn("Law 3: the manifest must declare unknown capabilities as COLLAPSE", self._errors())

    def test_manifest_must_agree_with_the_reference_decision_table(self) -> None:
        self._edit("CAPABILITY_MANIFEST.md", "| `guest_network` | `GuestMCPController` | Yes | DENY |", "| `guest_network` | `GuestMCPController` | Yes | ALLOW |")
        self.assertIn("Capability guest_network: manifest says ALLOW, capability_brokers.py says DENY", self._errors())

    def test_collapse_cue_with_an_invalid_action_fails(self) -> None:
        self._edit("COLLAPSE_CUES.md", "| `telemetry_loss` | COLLAPSE |", "| `telemetry_loss` | SHRUG |")
        self.assertIn("Collapse cue telemetry_loss lacks valid terminal action: SHRUG", self._errors())

    def test_unknown_capability_cue_must_collapse(self) -> None:
        self._edit("COLLAPSE_CUES.md", "| `unknown_capability_request` | COLLAPSE |", "| `unknown_capability_request` | DENY |")
        self.assertIn("Law 3: COLLAPSE_CUES.md must declare unknown_capability_request as COLLAPSE", self._errors())

    def test_component_claiming_code_that_does_not_exist_fails(self) -> None:
        self._edit("FIELD_ATLAS.md", "`guest/agent_probe_agent.py`", "`guest/no_such_agent.py`")
        self.assertIn("AgentProbeGuestAgent is marked implemented but guest/no_such_agent.py does not exist", self._errors())

    def test_removed_component_whose_code_still_exists_fails(self) -> None:
        self._edit("FIELD_ATLAS.md", "`sealed_replay.py`", "`kernel_laws.py`")
        self.assertIn("SealedReplayEngine is marked removed but kernel_laws.py still exists", self._errors())

    def test_unknown_component_status_fails(self) -> None:
        self._edit("FIELD_ATLAS.md", "| reference | `capability_brokers.py` |", "| production-grade | `capability_brokers.py` |")
        self.assertIn("CapabilityBroker has an unknown status: production-grade", self._errors())


class TestMarkdownTableParser(unittest.TestCase):
    def test_parses_headers_rows_and_strips_markup(self) -> None:
        text = "intro\n\n| A | B |\n|---|:---:|\n| `x` | *y* |\n| **z** | w |\n\ntrailing\n"
        self.assertEqual(
            parse_markdown_tables(text),
            [[{"A": "x", "B": "y"}, {"A": "z", "B": "w"}]],
        )

    def test_ignores_text_without_a_separator_row(self) -> None:
        self.assertEqual(parse_markdown_tables("| not | a table |\n| still | not |\n"), [])

    def test_drops_rows_with_the_wrong_cell_count(self) -> None:
        self.assertEqual(parse_markdown_tables("| A | B |\n|---|---|\n| only one |\n| 1 | 2 |\n"), [[{"A": "1", "B": "2"}]])


if __name__ == "__main__":
    unittest.main()
