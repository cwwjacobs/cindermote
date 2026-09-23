"""Tests for Contained API-Model Relay (Phase 4)."""

import os
import sys
import unittest
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from contained_model_relay import ContainedModelRelay, ModelRelayConfig


class TestContainedModelRelay(unittest.TestCase):
    def setUp(self) -> None:
        self.relay = ContainedModelRelay(
            ModelRelayConfig(
                endpoint="https://api.deepseek.com/v1",
                model_id="deepseek-chat",
            )
        )
        self.key_path = Path("/tmp/deepseek_key.txt")

    def test_relay_disallowed_endpoint_fails(self) -> None:
        invalid_relay = ContainedModelRelay(
            ModelRelayConfig(endpoint="https://malicious-endpoint.example.com")
        )
        with self.assertRaises(ValueError):
            invalid_relay.query_contained_model("key", [{"role": "user", "content": "hi"}])

    def test_live_deepseek_query_if_key_available(self) -> None:
        if not self.key_path.exists():
            self.skipTest("No /tmp/deepseek_key.txt found")

        key = self.key_path.read_text().strip()
        res = self.relay.query_contained_model(
            api_key=key,
            messages=[{"role": "user", "content": "Return the single word: OK"}],
            max_tokens=10,
        )
        self.assertEqual(res["status_code"], 200)
        self.assertTrue("deepseek" in res["model_used"].lower())

        self.assertIn("tokens_used", res)
        self.assertIn("response_hash", res)
        # Verify raw response remains in guest container scope only
        self.assertIn("raw_response_guest_only", res)


if __name__ == "__main__":
    unittest.main()
