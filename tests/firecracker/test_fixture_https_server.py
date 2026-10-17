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
FixtureState = _FIXTURE["FixtureState"]


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
            instance_id="b" * 32,
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
        self.assertEqual(json.loads(body)["instance_id"], "b" * 32)

    def test_private_identity_still_requires_control_authentication(self) -> None:
        handler = self._handler("/control/info")
        handler.do_GET()
        handler._send.assert_not_called()
        handler._reject.assert_called_once()

    def test_authenticated_and_public_identity_name_the_same_server_lifetime(self) -> None:
        public = self._handler("/fixture-info")
        private = self._handler("/control/info")
        private._authorized_control.return_value = True
        public.do_GET()
        private.do_GET()
        self.assertEqual(public._send.call_args.args[1], private._send.call_args.args[1])

    def test_counter_receipt_names_its_server_lifetime(self) -> None:
        handler = self._handler("/control/counts")
        handler._authorized_control.return_value = True
        handler.server.state.snapshot = lambda: {"post": 0}
        handler.do_GET()
        body = json.loads(handler._send.call_args.args[1])
        self.assertEqual(body["instance_id"], "b" * 32)
        self.assertEqual(body["counts"], {"post": 0})

    def test_each_server_start_has_a_new_public_nonce_that_reset_preserves(self) -> None:
        first = FixtureState("secret", "https://primary.example", "https://secondary.example", "a" * 64)
        second = FixtureState("secret", "https://primary.example", "https://secondary.example", "a" * 64)
        self.assertRegex(first.instance_id, r"^[0-9a-f]{32}$")
        self.assertNotEqual(first.instance_id, second.instance_id)
        original = first.instance_id
        first.reset()
        self.assertEqual(first.instance_id, original)


if __name__ == "__main__":
    unittest.main()
