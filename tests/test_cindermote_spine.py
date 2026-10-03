"""Tests for the Cindermote spine compatibility API and reference models."""

import sys
import unittest
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from cindermote_api import CindermoteService
from collapse_mesh import CollapseMesh
from mcp_target import MCPTargetConfig, MCPTargetContainer


class TestCindermoteSpine(unittest.TestCase):
    def test_mcp_target_enumeration_strips_raw_semantic_content(self) -> None:
        config = MCPTargetConfig("target-mcp", "npm://malicious-mcp")
        container = MCPTargetContainer(config)
        raw_manifest = {
            "tools": [
                {
                    "name": "safe_tool",
                    "description": "SECRET RAW PROMPT POISON TEXT THAT MUST NOT CROSS TO HOST",
                    "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}},
                }
            ],
            "prompts": [{"name": "prompt_1"}],
            "resources": [{"uri": "file:///etc/passwd"}],
        }
        summary = container.enumerate_metadata_only(raw_manifest)
        self.assertEqual(summary.tool_count, 1)
        self.assertEqual(summary.prompt_count, 1)
        self.assertEqual(summary.resource_count, 1)
        self.assertTrue(len(summary.tool_schema_hashes) == 1)
        # Verify raw description is not stored in summary fields
        self.assertNotIn("SECRET RAW PROMPT POISON TEXT", str(summary))

    def test_collapse_mesh_evaluation(self) -> None:
        mesh = CollapseMesh()
        ev = mesh.evaluate_event("real_secret_request", {"trigger": "read_env"})
        self.assertEqual(ev.terminal_action, "COLLAPSE")

    def test_cindermote_service_detonation_flow(self) -> None:
        service = CindermoteService()
        payload = {
            "target": {"id": "demo-mcp", "package_uri": "npm://demo"},
            "raw_manifest": {"tools": [{"name": "read_file"}]},
        }
        res = service.create_detonation(payload)
        self.assertEqual(res["status"], "DENIED")
        self.assertEqual(res["disposition"], "DENY")
        self.assertEqual(res["reason_code"], "HOST_NATIVE_EXECUTION_DISABLED")
        self.assertFalse(res["execution_started"])
        self.assertNotIn("ash_receipt", res)
        self.assertNotIn("sealed_replay", res)


if __name__ == "__main__":
    unittest.main()
