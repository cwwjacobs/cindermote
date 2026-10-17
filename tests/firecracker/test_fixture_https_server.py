from __future__ import annotations

import runpy
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock


_FIXTURE = runpy.run_path(str(Path(__file__).with_name("fixture_https_server.py")))
_validate_listener_binding = _FIXTURE["_validate_listener_binding"]
FixtureHandler = _FIXTURE["FixtureHandler"]


class FixtureListenerBindingTests(unittest.TestCase):
    def test_public_listener_uses_the_public_https_port(self) -> None:
        _validate_listener_binding("0.0.0.0", 443, "https://fixture.example")

    def test_tunneled_listener_may_use_a_different_loopback_port(self) -> None:
        _validate_listener_binding("127.0.0.1", 8443, "https://fixture.example")

    def test_mismatched_port_cannot_bind_publicly(self) -> None:
        with self.assertRaisesRegex(ValueError, "loopback-only"):
            _validate_listener_binding("0.0.0.0", 8443, "https://fixture.example")


class PublicFixtureIdentityTests(unittest.TestCase):
    def _handler(self, path: str):
        handler = FixtureHandler.__new__(FixtureHandler)
        handler.path = path
        handler.server = SimpleNamespace(state=SimpleNamespace(
            primary_origin="https://primary.example",
            unauthorized_origin="https://secondary.example",
            source_sha256="a" * 64,
            token="private-control-token",
        ))
        handler._authorized_control = Mock(return_value=False)
        handler._send = Mock()
        handler._reject = Mock()
        return handler

    def test_public_identity_contains_no_control_secret(self) -> None:
        handler = self._handler("/fixture-info")
        handler.do_GET()
        handler._authorized_control.assert_not_called()
        body = handler._send.call_args.args[1]
        self.assertNotIn(b"private-control-token", body)
        self.assertEqual(json.loads(body)["fixture_source_sha256"], "a" * 64)

    def test_private_identity_still_requires_control_authentication(self) -> None:
        handler = self._handler("/control/info")
        handler.do_GET()
        handler._send.assert_not_called()
        handler._reject.assert_called_once()


if __name__ == "__main__":
    unittest.main()
