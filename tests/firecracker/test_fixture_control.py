from __future__ import annotations

import io
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from tests.firecracker import e2e_supported_host as gate


class FixtureControlChannelTests(unittest.TestCase):
    def test_public_identity_request_has_no_bearer_token(self) -> None:
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{"fixture":true}'
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.object(gate.urllib.request, "build_opener", return_value=opener):
            self.assertEqual(gate._fixture_json("https://fixture.example", "/fixture-info", None), {"fixture": True})
        request = opener.open.call_args.args[0]
        self.assertIsNone(request.get_header("Authorization"))

    def test_private_control_request_uses_pinned_ca_and_loopback(self) -> None:
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{"reset":true}'
        opener = mock.Mock()
        opener.open.return_value = response
        ca_file = Path("fixture-ca.crt")
        with (
            mock.patch.object(gate.urllib.request, "build_opener", return_value=opener),
            mock.patch.object(gate.ssl, "create_default_context") as context,
        ):
            gate._fixture_json("https://127.0.0.1:8443", "/control/reset", "synthetic-token", method="POST", ca_file=ca_file)
        context.assert_called_once_with(cafile=ca_file)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "https://127.0.0.1:8443/control/reset")
        self.assertEqual(request.get_header("Authorization"), "Bearer synthetic-token")

    def test_control_endpoint_requires_loopback_https_and_ca(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ca_file = Path(directory) / "ca.crt"
            ca_file.write_bytes(b"synthetic certificate for path validation")
            self.assertEqual(gate._local_control_origin("https://127.0.0.1:8443/", ca_file), "https://127.0.0.1:8443")
            for origin, ca in (
                ("https://remote.example", ca_file),
                ("http://127.0.0.1:8443", ca_file),
                ("https://127.0.0.1:8443/path", ca_file),
                ("https://token@127.0.0.1:8443", ca_file),
                ("https://127.0.0.1:8443", None),
                (None, ca_file),
            ):
                with self.subTest(origin=origin), self.assertRaises(RuntimeError):
                    gate._local_control_origin(origin, ca)

    def test_redirects_cannot_forward_a_control_token(self) -> None:
        request = urllib.request.Request("https://127.0.0.1:8443/control/counts", headers={"Authorization": "Bearer synthetic-token"})
        with self.assertRaises(urllib.error.HTTPError):
            gate._NoFixtureRedirects().redirect_request(request, io.BytesIO(), 302, "redirect", {}, "https://outside.example/")


if __name__ == "__main__":
    unittest.main()
