from __future__ import annotations

import runpy
import unittest
from pathlib import Path


_FIXTURE = runpy.run_path(str(Path(__file__).with_name("fixture_https_server.py")))
_validate_listener_binding = _FIXTURE["_validate_listener_binding"]


class FixtureListenerBindingTests(unittest.TestCase):
    def test_public_listener_uses_the_public_https_port(self) -> None:
        _validate_listener_binding("0.0.0.0", 443, "https://fixture.example")

    def test_tunneled_listener_may_use_a_different_loopback_port(self) -> None:
        _validate_listener_binding("127.0.0.1", 8443, "https://fixture.example")

    def test_mismatched_port_cannot_bind_publicly(self) -> None:
        with self.assertRaisesRegex(ValueError, "loopback-only"):
            _validate_listener_binding("0.0.0.0", 8443, "https://fixture.example")


if __name__ == "__main__":
    unittest.main()
