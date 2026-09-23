from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from mote.detonate import _browser_destination_labels
from cindermote.observer.receipt import create_receipt, validate_receipt


SHA = "a" * 64
OTHER_SHA = "b" * 64


def _streams() -> dict[str, dict[str, object]]:
    return {
        "browser": {"complete": True, "event_count": 2, "observed_event_count": 2},
        "cdp": {"complete": True, "event_count": 1, "observed_event_count": 1},
        "egress": {"complete": True, "event_count": 2, "observed_event_count": 2},
        "vm": {"complete": True, "event_count": 2, "observed_event_count": 2},
    }


def _reduction_streams() -> dict[str, dict[str, object]]:
    return {
        source: {
            "declared_event_count": status["event_count"],
            "observed_event_count": status["observed_event_count"],
            "complete": status["complete"],
        }
        for source, status in _streams().items()
    }


def _valid_receipt() -> dict:
    runtime = {
        "admitted": True,
        "firecracker_version": "1.16.1",
        "firecracker_sha256": SHA,
        "jailer_sha256": SHA,
        "kernel_sha256": SHA,
        "rootfs_sha256": SHA,
        "rootfs_receipt_sha256": OTHER_SHA,
        "browser_version": "Chromium 150.0.7871.124",
        "browser_sha256": SHA,
        "job_image_sha256": OTHER_SHA,
        "host_runtime_tmpfs": True,
        "host_swap_disabled": True,
        "rootfs_read_only": True,
        "guest_writes_tmpfs_only": True,
        "network_mode": "explicit-proxy-only",
        "mmds_enabled": False,
        "vmm_identity": {
            "user": "cindermote-vmm",
            "group": "cindermote-vmm",
            "uid": 742,
            "gid": 743,
        },
        "jailer_supervision": {
            "external_supervisor": True,
            "parent_death_signal": "SIGTERM",
            "vmm_process_group_kill": "SIGKILL",
            "startup_reconciliation": "exact-owned-prefix",
        },
        "egress_worker": {
            "privilege_separated": True,
            "protocol_version": "cindermote.browser-egress-worker/v2",
            "user": "cindermote-proxy",
            "group": "cindermote-proxy",
            "uid": 744,
            "gid": 745,
            "no_new_privs": True,
            "dumpable": 0,
            "capabilities_zero": True,
        },
        "cgroup_limits": {
            "cpu.max": "100000 100000",
            "memory.max": str((1024 + 512) * 1024 * 1024),
            "memory.swap.max": "0",
            "pids.max": "256",
        },
    }
    stream_status = _streams()
    request_sha = OTHER_SHA
    policy_sha = SHA
    return {
        "identity": {
            "job_id": "mf-web-1234abcd",
            "artifact_sha256": SHA,
            "artifact_type": "browser-probe",
            "submitted_by": "test",
            "received_at": "2026-07-16T00:00:00Z",
        },
        "snapshot_policy": {
            "snapshot_sha256": runtime["rootfs_sha256"],
            "snapshot_verified_by": "test",
            "policy_version": "test-v1",
            "policy_hash": policy_sha,
            "memory_snapshots": "disabled-v1",
        },
        "isolation": {
            "mode": "firecracker",
            "namespace_used": True,
            "seccomp_loaded": True,
            "cgroups_used": True,
            "mlock_used": False,
            "jailer_used": True,
            "kvm_used": True,
            "host_runtime_tmpfs": True,
            "host_swap_disabled": True,
            "rootfs_read_only": True,
            "guest_writes_tmpfs_only": True,
        },
        "budgets_granted": {
            "wall_clock_sec": 20,
            "cpu_vcpu": 1,
            "ram_mib": 1024,
            "max_network_bytes": 16 * 1024 * 1024,
            "max_events": 100,
            "max_redirects": 8,
            "max_tabs": 1,
            "interaction": "passive navigation only",
            "fs_writes": "guest tmpfs only",
        },
        "capabilities": {
            "requested": ["browser.navigate"],
            "granted": ["browser.navigate"],
            "denied": [
                "browser.click",
                "browser.type",
                "browser.upload",
                "browser.download",
            ],
            "binding": {"request_sha256": request_sha, "job_id": "mf-web-1234abcd"},
        },
        "telemetry_summary": {
            "events_observed": 7,
            "streams": stream_status,
            "metadata_only": True,
        },
        "canaries_touched": {},
        "destinations_attempted": {},
        "detector_findings": [],
        "gate": {
            "policy_gate_decision": "ALLOW",
            "policy_gate_reason": "bounded_browser_navigation_clean",
            "human_gate_override": "none",
            "final_decision": "ALLOW",
            "final_authority": "policy_gate_autonomous",
            "override_blocked_by_fail_closed": False,
        },
        "outward_report": {
            "risk_level": "benign",
            "evidence": [],
            "capabilities_requested": ["browser.navigate"],
            "destinations": [],
            "canaries_tripped": [],
            "uncertainty": 0.0,
        },
        "purge": {
            "verified_externally": True,
            "processes_reaped": True,
            "cgroup_removed": True,
            "network_namespace_removed": True,
            "ram_jail_removed": True,
            "egress_worker_reaped": True,
        },
        "telemetry_incomplete": False,
        "budget_exhausted": False,
        "residual_uncertainty": 0.0,
        "browser_probe": {
            "schema_version": "cindermote.browser-probe-receipt/v2",
            "input": {
                "contract_version": "cindermote.browser-probe/v1",
                "url_sha256": SHA,
                "normalized_origin": "https://example.org",
                "authorized_origins": ["https://example.org"],
                "request_sha256": request_sha,
                "policy_hash": policy_sha,
                "navigation_mode": "passive",
            },
            "runtime": runtime,
            "evidence": {
                "schema_version": "cindermote.browser-evidence/v2",
                "sha256": SHA,
                "stream_status": stream_status,
                "events_observed": 7,
            },
            "artifacts": {
                "raw_retained": False,
                "attestation_complete": True,
                "dom_sha256": SHA,
                "visible_text_sha256": SHA,
                "screenshot_sha256": SHA,
                "console_event_count": 0,
            },
            "findings": [],
            "reduction": {
                "evidence_version": "cindermote.browser-evidence/v2",
                "complete": True,
                "telemetry_incomplete": False,
                "fail_closed": False,
                "decision": "ALLOW",
                "events_observed": 7,
                "streams": _reduction_streams(),
                "findings": [],
            },
        },
        "receipt_signature": SHA,
    }


class BrowserReceiptBindingTests(unittest.TestCase):
    def test_receipt_destination_labels_preserve_witness_meaning(self) -> None:
        events = [
            {
                "kind": "network_request",
                "source": "cdp",
                "web_origin": "https://example.org",
                "connect_authority": None,
                "disposition": "allowed",
            },
            {
                "kind": "network_request",
                "source": "egress",
                "web_origin": None,
                "connect_authority": "example.org:443",
                "disposition": "allowed",
            },
            {
                "kind": "network_request",
                "source": "egress",
                "web_origin": "http://example.org",
                "connect_authority": None,
                "disposition": "blocked",
            },
        ]
        self.assertEqual(
            _browser_destination_labels(events),
            {
                "example.org:443": ["proxy_connect_authority_allowed"],
                "http://example.org": ["proxy_http_origin_blocked"],
                "https://example.org": ["browser_cdp_web_origin_allowed"],
            },
        )

    def test_complete_browser_receipt_is_accepted(self) -> None:
        validate_receipt(_valid_receipt())

    def test_typed_destination_witnesses_are_accepted(self) -> None:
        candidate = _valid_receipt()
        candidate["destinations_attempted"] = {
            "example.org:443": ["proxy_connect_authority_allowed"],
            "http://example.org": [
                "browser_cdp_web_origin_allowed",
                "proxy_http_origin_allowed",
            ],
            "https://example.org": ["browser_cdp_web_origin_allowed"],
        }
        candidate["outward_report"]["destinations"] = sorted(
            candidate["destinations_attempted"]
        )
        validate_receipt(candidate)

    def test_v1_signed_schema_is_not_reinterpreted_as_v2(self) -> None:
        legacy_receipt = _valid_receipt()
        legacy_receipt["browser_probe"]["schema_version"] = (
            "cindermote.browser-probe-receipt/v1"
        )
        with self.assertRaises(ValueError):
            validate_receipt(legacy_receipt)

        legacy_evidence = _valid_receipt()
        legacy_evidence["browser_probe"]["evidence"]["schema_version"] = (
            "cindermote.browser-evidence/v1"
        )
        legacy_evidence["browser_probe"]["reduction"]["evidence_version"] = (
            "cindermote.browser-evidence/v1"
        )
        with self.assertRaises(ValueError):
            validate_receipt(legacy_evidence)

    def test_proxy_and_cdp_witness_types_cannot_be_interchanged(self) -> None:
        candidates = []

        origin_key = _valid_receipt()
        origin_key["destinations_attempted"] = {
            "https://example.org": [
                "browser_cdp_web_origin_allowed",
                "proxy_connect_authority_allowed",
            ]
        }
        origin_key["outward_report"]["destinations"] = ["https://example.org"]
        candidates.append(origin_key)

        authority_key = _valid_receipt()
        authority_key["destinations_attempted"] = {
            "example.org:443": ["browser_cdp_web_origin_allowed"]
        }
        authority_key["outward_report"]["destinations"] = ["example.org:443"]
        candidates.append(authority_key)

        proxy_claims_https_origin = _valid_receipt()
        proxy_claims_https_origin["destinations_attempted"] = {
            "https://example.org": ["proxy_http_origin_allowed"]
        }
        proxy_claims_https_origin["outward_report"]["destinations"] = [
            "https://example.org"
        ]
        candidates.append(proxy_claims_https_origin)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                validate_receipt(candidate)

    def test_browser_section_is_required_iff_browser_artifact(self) -> None:
        missing = _valid_receipt()
        del missing["browser_probe"]
        with self.assertRaises(ValueError):
            validate_receipt(missing)

        unexpected = _valid_receipt()
        unexpected["identity"]["artifact_type"] = "python-script"
        with self.assertRaises(ValueError):
            validate_receipt(unexpected)

    def test_nested_commitments_cannot_be_relabelled_or_unbound(self) -> None:
        mutations = []

        candidate = _valid_receipt()
        candidate["capabilities"]["binding"]["request_sha256"] = SHA
        mutations.append(candidate)

        candidate = _valid_receipt()
        candidate["browser_probe"]["evidence"]["events_observed"] = 8
        mutations.append(candidate)

        candidate = _valid_receipt()
        candidate["browser_probe"]["runtime"]["rootfs_sha256"] = OTHER_SHA
        mutations.append(candidate)

        candidate = _valid_receipt()
        candidate["browser_probe"]["artifacts"]["raw_retained"] = True
        mutations.append(candidate)

        candidate = _valid_receipt()
        candidate["purge"]["egress_worker_reaped"] = False
        mutations.append(candidate)

        candidate = _valid_receipt()
        candidate["gate"]["policy_gate_decision"] = "DENY"
        mutations.append(candidate)

        candidate = _valid_receipt()
        candidate["browser_probe"]["runtime"]["raw_page_text"] = "SECRET PAGE CONTENT"
        mutations.append(candidate)

        candidate = _valid_receipt()
        candidate["browser_probe"]["runtime"]["cgroup_limits"]["memory.swap.max"] = "max"
        mutations.append(candidate)

        candidate = _valid_receipt()
        candidate["destinations_attempted"] = {
            "https://example.org/?access_token=SECRET": [
                "browser_cdp_web_origin_allowed"
            ]
        }
        candidate["outward_report"]["destinations"] = [
            "https://example.org/?access_token=SECRET"
        ]
        mutations.append(candidate)

        candidate = _valid_receipt()
        extra = {
            "finding_id": "web_active_interaction_attempt",
            "count": 1,
            "severity": "CRITICAL",
        }
        candidate["browser_probe"]["findings"] = [extra]
        candidate["detector_findings"] = [
            {"rule_id": extra["finding_id"], "count": 1, "severity": "CRITICAL"}
        ]
        candidate["outward_report"]["evidence"] = [
            {
                "tap_category": "syscall_class",
                "rule_id": extra["finding_id"],
                "count": 1,
            }
        ]
        candidate["outward_report"]["risk_level"] = "hostile"
        mutations.append(candidate)

        for candidate in mutations:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                validate_receipt(candidate)

    def test_proxy_identity_is_named_unique_and_distinct_from_vmm(self) -> None:
        for field, value in (
            ("user", "nobody"),
            ("group", "nogroup"),
            ("uid", 65534),
            ("gid", 65533),
            ("uid", 742),
            ("gid", 743),
        ):
            candidate = _valid_receipt()
            candidate["browser_probe"]["runtime"]["egress_worker"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                validate_receipt(candidate)

    def test_stream_completeness_and_per_source_counts_are_bound(self) -> None:
        incomplete = _valid_receipt()
        incomplete["browser_probe"]["evidence"]["stream_status"]["cdp"][
            "complete"
        ] = False
        incomplete["telemetry_summary"]["streams"]["cdp"]["complete"] = False
        incomplete["browser_probe"]["reduction"]["streams"]["cdp"][
            "complete"
        ] = False
        with self.assertRaisesRegex(ValueError, "completeness"):
            validate_receipt(incomplete)

        redistributed = _valid_receipt()
        for section in (
            redistributed["browser_probe"]["evidence"]["stream_status"],
            redistributed["telemetry_summary"]["streams"],
        ):
            section["browser"]["event_count"] = 1
            section["cdp"]["event_count"] = 2
        reduction_streams = redistributed["browser_probe"]["reduction"]["streams"]
        reduction_streams["browser"]["declared_event_count"] = 1
        reduction_streams["cdp"]["declared_event_count"] = 2
        with self.assertRaisesRegex(ValueError, "count mismatch finding"):
            validate_receipt(redistributed)

    def test_truncated_attestation_is_a_signable_fail_closed_receipt(self) -> None:
        receipt = _valid_receipt()
        receipt["browser_probe"]["artifacts"]["attestation_complete"] = False
        receipt["browser_probe"]["evidence"]["events_observed"] = 8
        receipt["browser_probe"]["evidence"]["stream_status"]["cdp"]["event_count"] = 2
        receipt["browser_probe"]["evidence"]["stream_status"]["cdp"]["observed_event_count"] = 2
        receipt["telemetry_summary"]["events_observed"] = 8
        receipt["telemetry_summary"]["streams"]["cdp"]["event_count"] = 2
        receipt["telemetry_summary"]["streams"]["cdp"]["observed_event_count"] = 2
        reduction = receipt["browser_probe"]["reduction"]
        reduction["complete"] = False
        reduction["telemetry_incomplete"] = True
        reduction["fail_closed"] = True
        reduction["decision"] = "DENY"
        reduction["events_observed"] = 8
        reduction["streams"]["cdp"]["declared_event_count"] = 2
        reduction["streams"]["cdp"]["observed_event_count"] = 2
        finding = {
            "finding_id": "web_cdp_telemetry_loss",
            "count": 1,
            "severity": "CRITICAL",
        }
        reduction["findings"] = [finding]
        receipt["browser_probe"]["findings"] = [finding]
        receipt["detector_findings"] = [
            {"rule_id": finding["finding_id"], "count": 1, "severity": "CRITICAL"}
        ]
        receipt["outward_report"]["risk_level"] = "hostile"
        receipt["outward_report"]["evidence"] = [
            {
                "tap_category": "syscall_class",
                "rule_id": finding["finding_id"],
                "count": 1,
            }
        ]
        receipt["outward_report"]["uncertainty"] = 1.0
        receipt["residual_uncertainty"] = 1.0
        receipt["gate"].update(
            {
                "policy_gate_decision": "DENY",
                "policy_gate_reason": "known_bad_behavior_detected",
                "final_decision": "DENY",
                "final_authority": "fail_closed_infrastructure_gate",
            }
        )
        receipt["telemetry_incomplete"] = True

        validate_receipt(receipt)

    def test_create_receipt_refuses_browser_identity_without_browser_section(self) -> None:
        valid = _valid_receipt()
        with tempfile.TemporaryDirectory() as temporary, self.assertRaises(ValueError):
            create_receipt(
                identity=copy.deepcopy(valid["identity"]),
                snapshot_policy=copy.deepcopy(valid["snapshot_policy"]),
                isolation=copy.deepcopy(valid["isolation"]),
                budgets_granted={},
                capabilities=copy.deepcopy(valid["capabilities"]),
                telemetry_summary=copy.deepcopy(valid["telemetry_summary"]),
                canaries_touched={},
                destinations_attempted={},
                detector_findings=[],
                gate=copy.deepcopy(valid["gate"]),
                outward_report=copy.deepcopy(valid["outward_report"]),
                purge=copy.deepcopy(valid["purge"]),
                telemetry_incomplete=False,
                budget_exhausted=False,
                residual_uncertainty=0.0,
                key_path=Path(temporary) / "observer.key",
                browser_probe=None,
            )


if __name__ == "__main__":
    unittest.main()
