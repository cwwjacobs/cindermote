from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cindermote.mote.detonate import load_policy
from tests.firecracker.e2e_supported_host import (
    CASES,
    RECEIPTS_DIR,
    case_request,
    collect_gate_provenance,
    run_gate,
    verify_gate_provenance,
)


class GateProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.project = Path(self.temporary.name)
        self.cache = self.project / "cache"
        for directory in ("src", "fixture", "policy", "cache/images"):
            (self.project / directory).mkdir(parents=True, exist_ok=True)
        (self.project / "src/runtime.py").write_text("VALUE = 1\n", encoding="utf-8")
        (self.project / "src/untracked.py").write_text("UNTRACKED = True\n", encoding="utf-8")
        (self.project / "fixture/server.py").write_text("FIXTURE = 1\n", encoding="utf-8")
        (self.project / "policy/hotcell-policy.json").write_text("{}\n", encoding="ascii")
        rootfs = self.project / "cache/images/browser-rootfs.ext4"
        rootfs.write_bytes(b"rootfs-test-bytes")
        rootfs_sha256 = hashlib.sha256(rootfs.read_bytes()).hexdigest()
        receipt = self.project / "cache/images/browser-rootfs.receipt.json"
        receipt.write_text(
            json.dumps(
                {
                    "schema_version": "cindermote.browser-rootfs/v1",
                    "rootfs": {"sha256": rootfs_sha256},
                },
                sort_keys=True,
            )
            + "\n",
            encoding="ascii",
        )
        receipt_sha256 = hashlib.sha256(receipt.read_bytes()).hexdigest()
        (self.project / "policy/firecracker-assets.lock.json").write_text(
            json.dumps(
                {
                    "browser_rootfs": {
                        "path": "images/browser-rootfs.ext4",
                        "sha256": rootfs_sha256,
                        "build_receipt_path": "images/browser-rootfs.receipt.json",
                        "build_receipt_sha256": receipt_sha256,
                        "required_receipt_schema": "cindermote.browser-rootfs/v1",
                    }
                },
                sort_keys=True,
            )
            + "\n",
            encoding="ascii",
        )
        self.options = {
            "source_scopes": ("src", "fixture", "policy"),
            "fixture_sources": ("fixture/server.py",),
            "policy_path": "policy/hotcell-policy.json",
            "asset_lock_path": "policy/firecracker-assets.lock.json",
            "cache_dir": self.cache,
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def collect(self) -> dict:
        with mock.patch(
            "tests.firecracker.e2e_supported_host._git_head", return_value="a" * 40
        ):
            return collect_gate_provenance(self.project, **self.options)

    def verify(self, expected: dict) -> None:
        with mock.patch(
            "tests.firecracker.e2e_supported_host._git_head", return_value="a" * 40
        ):
            verify_gate_provenance(expected, self.project, **self.options)

    def test_manifest_includes_dirty_untracked_source_and_reverifies(self) -> None:
        provenance = self.collect()
        paths = {item["path"] for item in provenance["source_snapshot"]["files"]}
        self.assertIn("src/untracked.py", paths)
        self.assertEqual(
            provenance["browser_rootfs"]["sha256"],
            provenance["browser_rootfs"]["lock_declared_sha256"],
        )
        self.assertEqual(
            provenance["fixture_sources"][0]["sha256"],
            hashlib.sha256((self.project / "fixture/server.py").read_bytes()).hexdigest(),
        )
        self.assertEqual(provenance, self.collect())
        self.assertEqual(provenance["git_head"], "a" * 40)
        self.verify(provenance)

        with mock.patch(
            "tests.firecracker.e2e_supported_host._git_head", return_value="b" * 40
        ):
            with self.assertRaisesRegex(AssertionError, "provenance changed"):
                verify_gate_provenance(provenance, self.project, **self.options)

    def test_source_edit_or_new_scoped_file_invalidates_snapshot(self) -> None:
        provenance = self.collect()
        (self.project / "src/runtime.py").write_text("VALUE = 2\n", encoding="utf-8")
        with self.assertRaisesRegex(AssertionError, "provenance changed"):
            self.verify(provenance)
        (self.project / "src/runtime.py").write_text("VALUE = 1\n", encoding="utf-8")
        provenance = self.collect()
        (self.project / "src/new_untracked.py").write_text("NEW = True\n", encoding="utf-8")
        with self.assertRaisesRegex(AssertionError, "provenance changed"):
            self.verify(provenance)

    def test_rootfs_artifact_or_receipt_mismatch_fails_closed(self) -> None:
        provenance = self.collect()
        rootfs = self.project / "cache/images/browser-rootfs.ext4"
        rootfs.write_bytes(b"changed")
        with self.assertRaisesRegex(AssertionError, "rootfs differs"):
            self.verify(provenance)
        rootfs.write_bytes(b"rootfs-test-bytes")
        provenance = self.collect()
        receipt = self.project / "cache/images/browser-rootfs.receipt.json"
        receipt.write_bytes(receipt.read_bytes() + b" ")
        with self.assertRaisesRegex(AssertionError, "build receipt differs"):
            self.verify(provenance)


class SupportedHostGateContractTests(unittest.TestCase):
    def test_rerun_invalidates_an_older_gate_before_input_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "firecracker-e2e-gate.json"
            output.write_text('{"status":"PASS"}\n', encoding="ascii")
            with (
                mock.patch(
                    "tests.firecracker.e2e_supported_host.os.geteuid",
                    return_value=1000,
                ),
                self.assertRaisesRegex(RuntimeError, "must run as root"),
            ):
                run_gate(
                    origin="https://fixture.example.org",
                    unauthorized_origin="https://secondary.example.org",
                    token_file=Path(temporary) / "missing-token",
                    output_path=output,
                )
            self.assertFalse(output.exists())

    def test_every_fixture_case_fits_the_runtime_policy_before_kvm(self) -> None:
        ceilings = load_policy()["browser_budgets"]
        for case_name, path, _finding in CASES:
            request = case_request("https://fixture.example.org", path)
            with self.subTest(case=case_name):
                for name, value in request["budgets"].items():
                    self.assertLessEqual(value, ceilings[name])


@unittest.skipUnless(
    os.environ.get("CINDERMOTE_RUN_KVM_E2E") == "1",
    "set CINDERMOTE_RUN_KVM_E2E=1 with controlled HTTPS fixture variables",
)
class SupportedHostFirecrackerE2E(unittest.TestCase):
    def test_real_kvm_browser_and_teardown_gate(self) -> None:
        origin = os.environ["CINDERMOTE_E2E_ORIGIN"]
        unauthorized = os.environ["CINDERMOTE_E2E_UNAUTHORIZED_ORIGIN"]
        token_file = Path(os.environ["CINDERMOTE_E2E_CONTROL_TOKEN_FILE"])
        result = run_gate(
            origin=origin,
            unauthorized_origin=unauthorized,
            token_file=token_file,
            output_path=RECEIPTS_DIR / "firecracker-e2e-gate.json",
        )
        self.assertEqual(result["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
