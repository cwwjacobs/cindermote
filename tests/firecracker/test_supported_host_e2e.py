from __future__ import annotations

import hashlib
import json
import os
import secrets
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from cindermote.mote.detonate import _canonical_hash, load_policy
from cindermote.observer.receipt import sign_receipt, validate_receipt, verify_signature
from tests.firecracker import e2e_supported_host as gate
from tests.firecracker.test_browser_receipt import _valid_receipt
from tests.firecracker.e2e_supported_host import (
    CASES,
    RECEIPTS_DIR,
    case_request,
    collect_gate_provenance,
    run_gate,
    validate_browser_evidence,
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
    def test_gate_accepts_current_host_owned_browser_evidence(self) -> None:
        evidence = {
            "evidence_version": "cindermote.browser-evidence/v2",
            "events": [],
            "streams": {
                source: {"complete": False, "event_count": 0}
                for source in ("browser", "cdp", "egress", "vm")
            },
        }
        self.assertEqual(validate_browser_evidence(evidence), evidence)

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


class GateReceiptBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.key = secrets.token_bytes(32)
        self.key_path = self.root / "observer.key"
        self.key_path.write_bytes(self.key)
        self.request = case_request("https://example.org", "/case/clean")
        self.receipt = _valid_receipt()
        events = []
        counts = {source: 0 for source in ("browser", "cdp", "egress", "vm")}
        for source, kind, disposition, origin, authority in (
            ("vm", "lifecycle", "started", None, None),
            ("browser", "lifecycle", "started", None, None),
            ("cdp", "navigation", "committed", "https://example.org", None),
            ("browser", "browser_sandbox", "active", None, None),
            ("browser", "lifecycle", "stopped", None, None),
            ("egress", "network_request", "allowed", None, "example.org:443"),
            ("vm", "lifecycle", "stopped", None, None),
        ):
            events.append({
                "source": source,
                "sequence": counts[source],
                "kind": kind,
                "disposition": disposition,
                "web_origin": origin,
                "connect_authority": authority,
            })
            counts[source] += 1
        evidence = {
            "evidence_version": "cindermote.browser-evidence/v2",
            "events": events,
            "streams": {
                source: {"complete": True, "event_count": count}
                for source, count in counts.items()
            },
        }
        job_id = self.receipt["identity"]["job_id"]
        evidence_path = self.root / f"{job_id}.browser-evidence.json"
        evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
        browser = self.receipt["browser_probe"]
        browser["input"].update({
            "request_sha256": _canonical_hash(self.request),
            "url_sha256": hashlib.sha256(self.request["url"].encode("utf-8")).hexdigest(),
        })
        self.receipt["capabilities"]["binding"]["request_sha256"] = _canonical_hash(self.request)
        self.receipt["budgets_granted"].update(self.request["budgets"])
        statuses = {
            source: {"complete": True, "event_count": count, "observed_event_count": count}
            for source, count in counts.items()
        }
        browser["evidence"].update({
            "sha256": hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
            "stream_status": statuses,
            "events_observed": len(events),
        })
        browser["reduction"] = gate.reduce_browser_evidence(evidence, self.request)
        self.receipt["telemetry_summary"].update({
            "events_observed": len(events), "streams": statuses,
        })
        self._persist_receipt()
        patcher = mock.patch.multiple(
            gate,
            OBSERVER_KEY_PATH=self.key_path,
            RECEIPTS_DIR=self.root,
            _owned_stale_job_tokens=mock.Mock(return_value=set()),
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _persist_receipt(self) -> None:
        self.receipt.pop("receipt_signature", None)
        self.receipt["receipt_signature"] = sign_receipt(self.receipt, self.key)
        validate_receipt(self.receipt)
        job_id = self.receipt["identity"]["job_id"]
        (self.root / f"{job_id}.json").write_text(json.dumps(self.receipt), encoding="utf-8")

    def test_matching_signed_persisted_case_is_accepted(self) -> None:
        result = gate._verify_probe_receipt(self.receipt, self.request, None)
        self.assertEqual(result["job_id"], self.receipt["identity"]["job_id"])
        self.assertEqual(result["decision"], "ALLOW")

    def test_signed_receipt_for_another_path_on_the_same_origin_is_rejected(self) -> None:
        other_request = case_request("https://example.org", "/case/unauthorized")
        self.assertTrue(verify_signature(self.receipt, self.key))
        with self.assertRaisesRegex(AssertionError, "exact fixture request"):
            gate._verify_probe_receipt(self.receipt, other_request, None)

    def test_signed_receipt_with_different_granted_budgets_is_rejected(self) -> None:
        self.receipt["budgets_granted"]["max_events"] += 1
        self._persist_receipt()
        with self.assertRaisesRegex(AssertionError, "budgets differ"):
            gate._verify_probe_receipt(self.receipt, self.request, None)

    def _run_gate_with_cases(self, cases: tuple, *, counter_instance: str = "c" * 32) -> dict:
        fixture_hash = "a" * 64
        provenance = {
            "fixture_sources": [{"path": gate.FIXTURE_SOURCE_PATHS[0], "sha256": fixture_hash}],
            "browser_rootfs": {
                "sha256": self.receipt["browser_probe"]["runtime"]["rootfs_sha256"],
                "build_receipt": {
                    "sha256": self.receipt["browser_probe"]["runtime"]["rootfs_receipt_sha256"],
                },
            },
        }
        fixture_info = {
            "schema_version": "cindermote.e2e-fixture/v1",
            "primary_origin": "https://example.org",
            "unauthorized_origin": "https://secondary.example.org",
            "fixture_source_sha256": fixture_hash,
            "instance_id": "c" * 32,
        }

        def fixture_json(_origin: str, path: str, _token: str, **_options: object) -> dict:
            if path in {"/fixture-info", "/control/info"}:
                return fixture_info
            if path == "/control/counts":
                return {
                    "schema_version": "cindermote.e2e-fixture/v1",
                    "instance_id": counter_instance,
                    "counts": {"post": 0, "websocket": 0, "popup": 0, "unauthorized": 0},
                }
            return {"reset": True}

        output = self.root / "gate.json"
        with (
            mock.patch.object(gate.os, "geteuid", return_value=0),
            mock.patch.multiple(
                gate,
                CASES=cases,
                _read_private_token=mock.Mock(return_value="test-token"),
                collect_gate_provenance=mock.Mock(return_value=provenance),
                verify_gate_provenance=mock.Mock(),
                preflight_firecracker=mock.Mock(return_value=SimpleNamespace(
                    ready=True, to_dict=lambda: {"ready": True},
                )),
                _fixture_json=fixture_json,
                detonate_browser_probe=mock.Mock(return_value=self.receipt),
            ),
            self.assertRaises(AssertionError),
        ):
            run_gate(
                origin="https://example.org",
                unauthorized_origin="https://secondary.example.org",
                token_file=self.root / "unused-token",
                output_path=output,
            )
        result = json.loads(output.read_text(encoding="utf-8"))
        self.assertTrue(verify_signature(result, self.key))
        self.assertEqual(result["status"], "FAIL")
        return result

    def test_gate_rejects_reusing_one_signed_job_for_two_cases(self) -> None:
        result = self._run_gate_with_cases((
            ("first", "/case/clean", None),
            ("second", "/case/clean", None),
        ))
        self.assertIn("reused a browser job", result["failure"])
        self.assertEqual(len(result["cases"]), 1)
        self.assertEqual(result["failed_case"]["case"], "second")

    def test_failed_expectation_is_bound_to_the_signed_failure_artifact(self) -> None:
        result = self._run_gate_with_cases((
            ("expected-deny", "/case/clean", "web_active_interaction_attempt"),
        ))
        failed = result["failed_case"]
        self.assertEqual(result["cases"], [])
        self.assertEqual(failed["case"], "expected-deny")
        self.assertEqual(failed["job_id"], self.receipt["identity"]["job_id"])
        self.assertEqual(failed["decision"], "ALLOW")
        self.assertTrue(failed["receipt_artifacts_verified"])
        receipt_path = self.root / f"{failed['job_id']}.json"
        self.assertEqual(failed["receipt_sha256"], hashlib.sha256(receipt_path.read_bytes()).hexdigest())
        self.assertEqual(failed["evidence_sha256"], self.receipt["browser_probe"]["evidence"]["sha256"])

    def test_restarted_fixture_cannot_supply_fresh_zero_counters(self) -> None:
        result = self._run_gate_with_cases((), counter_instance="d" * 32)
        self.assertIn("fixture instance changed", result["failure"])
        self.assertEqual(result["fixture"]["instance_id"], "c" * 32)
        self.assertEqual(result["fixture"]["counter_scope"]["model"], "shared-fixture-instance")
        self.assertFalse(result["fixture"]["counter_scope"]["origin_labels_are_independent"])


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
