from __future__ import annotations

import copy
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


class FixtureInstanceBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.primary = "https://primary.example"
        self.secondary = "https://secondary.example"
        self.local = "https://127.0.0.1:8443"
        self.ca_file = Path("fixture-ca.crt")
        self.info = {
            "schema_version": "cindermote.e2e-fixture/v1",
            "primary_origin": self.primary,
            "unauthorized_origin": self.secondary,
            "fixture_source_sha256": "a" * 64,
            "instance_id": "b" * 32,
        }

    def test_private_identity_is_obtained_first_and_both_public_requests_are_token_free(self) -> None:
        with mock.patch.object(gate, "_fixture_json", return_value=self.info) as fetch:
            observed = gate._verify_fixture_identity(
                self.primary, self.secondary, "a" * 64, "private-token", self.local, self.ca_file,
            )
        self.assertEqual(observed, self.info)
        self.assertEqual(fetch.call_args_list, [
            mock.call(self.local, "/control/info", "private-token", ca_file=self.ca_file),
            mock.call(self.primary, "/fixture-info", None),
            mock.call(self.secondary, "/fixture-info", None),
        ])

    def test_public_instance_must_match_authenticated_loopback_for_each_origin(self) -> None:
        for mismatched_origin in (self.primary, self.secondary):
            with self.subTest(origin=mismatched_origin):
                def info_for(origin: str, _path: str, _token: str | None, **_options: object) -> dict:
                    info = copy.deepcopy(self.info)
                    if origin == mismatched_origin:
                        info["instance_id"] = "c" * 32
                    return info

                with mock.patch.object(gate, "_fixture_json", side_effect=info_for):
                    with self.assertRaisesRegex(RuntimeError, "instance identities differ"):
                        gate._verify_fixture_identity(
                            self.primary, self.secondary, "a" * 64, "private-token", self.local, self.ca_file,
                        )

    def test_default_route_binds_both_public_origins_to_the_same_instance(self) -> None:
        with mock.patch.object(gate, "_fixture_json", return_value=self.info) as fetch:
            observed = gate._verify_fixture_identity(
                self.primary, self.secondary, "a" * 64, "private-token", None, None,
            )
        self.assertEqual(observed["instance_id"], "b" * 32)
        self.assertEqual(fetch.call_args_list, [
            mock.call(self.primary, "/fixture-info", None),
            mock.call(self.secondary, "/fixture-info", None),
        ])
        different_instance = dict(self.info, instance_id="c" * 32)
        with mock.patch.object(gate, "_fixture_json", side_effect=[self.info, different_instance]):
            with self.assertRaisesRegex(RuntimeError, "instance identities differ"):
                gate._verify_fixture_identity(
                    self.primary, self.secondary, "a" * 64, "private-token", None, None,
                )

    def test_malformed_authenticated_nonce_stops_before_any_public_request(self) -> None:
        for instance_id in (None, "", "b" * 31, "z" * 32, "b" * 33):
            with self.subTest(instance_id=instance_id):
                malformed = dict(self.info, instance_id=instance_id)
                with mock.patch.object(gate, "_fixture_json", return_value=malformed) as fetch:
                    with self.assertRaisesRegex(RuntimeError, "instance identity is malformed"):
                        gate._verify_fixture_identity(
                            self.primary, self.secondary, "a" * 64, "private-token", self.local, self.ca_file,
                        )
                    self.assertEqual(fetch.call_count, 1)

    def test_instance_match_does_not_substitute_for_source_and_origin_checks(self) -> None:
        for changes in (
            {"fixture_source_sha256": "c" * 64},
            {"primary_origin": self.secondary},
            {"unauthorized_origin": self.primary},
            {"extra": "unrecognized"},
        ):
            with self.subTest(changes=changes):
                malformed = dict(self.info, **changes)
                with mock.patch.object(gate, "_fixture_json", return_value=malformed) as fetch:
                    with self.assertRaisesRegex(RuntimeError, "identity check failed"):
                        gate._verify_fixture_identity(
                            self.primary, self.secondary, "a" * 64, "private-token", self.local, self.ca_file,
                        )
                    self.assertEqual(fetch.call_count, 1)


if __name__ == "__main__":
    unittest.main()
