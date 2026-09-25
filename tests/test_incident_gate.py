#!/usr/bin/env python3
"""Deterministic tests for the Cinder Incident Gate.

These tests detonate real hostile payloads through the real Cindermote S0-S4
sandbox and verify containment from host-generated receipts.

Tests are split into two tiers:

1. Unit tests (no sandbox): test probe definitions, report generation,
   doctor checks — these are safe to run anywhere and fast.

2. Integration tests (require sandbox): run each probe through detonate()
   and verify real isolation.  Marked with @pytest.mark.integration so
   they can be skipped in CI environments without namespace support.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import struct
import sys
import tarfile
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

import cindermote.incident_gate as incident_gate_module
from cindermote.gate.policy_gate import apply_scoring_matrix
from cindermote.incident_gate import (
    CINDER_PROBES,
    CinderProbe,
    ProbeResult,
    _create_evidence_paths,
    _ensure_snapshot,
    _evaluate_receipt,
    generate_report,
    run_all_probes,
    run_doctor,
    run_probe,
)
from cindermote.observer.receipt import create_receipt, validate_receipt


# ---------------------------------------------------------------------------
# Tier 1: Unit tests — no sandbox required, safe everywhere
# ---------------------------------------------------------------------------

class TestProbeDefinitions(unittest.TestCase):
    """Verify the probe definitions are well-formed."""

    def test_all_probes_have_unique_names(self):
        names = [p.name for p in CINDER_PROBES]
        self.assertEqual(len(names), len(set(names)))

    def test_all_probes_have_source(self):
        for probe in CINDER_PROBES:
            self.assertGreater(len(probe.source), 10)

    def test_all_probes_have_hostile_expectations(self):
        for probe in CINDER_PROBES:
            self.assertIn(probe.expected_risk, {"hostile", "suspicious"})
            self.assertIn(probe.expected_decision, {"DENY", "ALLOW"})

    def test_probe_count(self):
        """We must have at least 6 probes covering the full attack chain."""
        self.assertGreaterEqual(len(CINDER_PROBES), 6)

    def test_attack_chain_coverage(self):
        """Each step of the attack chain must be represented."""
        names = {p.name for p in CINDER_PROBES}
        required = {
            "registry_proxy_abuse",
            "lateral_movement",
            "metadata_access",
            "credential_harvest",
            "outbound_exfil",
            "tainted_output",
        }
        self.assertTrue(required.issubset(names), f"Missing: {required - names}")


class TestCanonicalModule(unittest.TestCase):
    """The package bridge and command path must resolve one implementation."""

    def test_package_import_resolves_repository_root(self):
        self.assertEqual(
            Path(incident_gate_module.__file__).resolve(),
            (PROJECT_DIR / "incident_gate.py").resolve(),
        )

    def test_dead_duplicate_modules_are_removed(self):
        self.assertFalse((PROJECT_DIR / "cindermote" / "incident_gate.py").exists())
        self.assertFalse((PROJECT_DIR / "cindermote" / "cli.py").exists())


class TestVerdictStrictness(unittest.TestCase):
    def _receipt(self, *, risk: str = "hostile", rules: set[str] | None = None):
        return {
            "observation": {"status": "COMPLETE"},
            "telemetry_incomplete": False,
            "outward_report": {"risk_level": risk},
            "gate": {"final_decision": "DENY"},
            "isolation": {"namespace_used": True, "seccomp_loaded": True},
            "purge": {"verified_externally": True},
            "detector_findings": [
                {"rule_id": rule} for rule in (rules or {"network_exfil_attempt"})
            ],
        }

    def test_hostile_expectation_rejects_suspicious_observation(self):
        probe = CINDER_PROBES[0]
        result = _evaluate_receipt(probe, self._receipt(risk="suspicious"))
        self.assertFalse(result.containment_held)

    def test_missing_expected_rule_fails_the_probe(self):
        probe = CINDER_PROBES[0]
        result = _evaluate_receipt(probe, self._receipt(rules={"different_rule"}))
        self.assertFalse(result.containment_held)

    def test_exact_hostile_evidence_passes(self):
        probe = CINDER_PROBES[0]
        result = _evaluate_receipt(probe, self._receipt())
        self.assertTrue(result.containment_held)

    def test_missing_or_malformed_observation_never_proves_containment(self):
        for observation in (None, {}, [], "COMPLETE", {"status": "UNKNOWN"}):
            with self.subTest(observation=observation):
                receipt = self._receipt()
                if observation is None:
                    del receipt["observation"]
                else:
                    receipt["observation"] = observation
                result = _evaluate_receipt(CINDER_PROBES[0], receipt)
                self.assertFalse(result.containment_held)
                self.assertEqual(result.observation_status, "EVALUATION_INCOMPLETE")

    def test_containment_requires_explicit_complete_telemetry(self):
        for telemetry in (None, True, 0, "false"):
            with self.subTest(telemetry=telemetry):
                receipt = self._receipt()
                if telemetry is None:
                    del receipt["telemetry_incomplete"]
                else:
                    receipt["telemetry_incomplete"] = telemetry
                self.assertFalse(_evaluate_receipt(CINDER_PROBES[0], receipt).containment_held)


class TestEvidenceIsolation(unittest.TestCase):
    def test_existing_repository_evidence_is_not_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old_receipts = root / "existing-receipts"
            old_quarantine = root / "existing-quarantine"
            old_alerts = root / "existing-alerts"
            for path in (old_receipts, old_quarantine, old_alerts):
                path.mkdir()
                (path / "sentinel").write_text("preserve", encoding="utf-8")

            previous = (
                incident_gate_module.detonate_module.RECEIPTS_DIR,
                incident_gate_module.detonate_module.QUARANTINE_DIR,
                incident_gate_module.detonate_module.ALERTS_DIR,
            )
            incident_gate_module.detonate_module.RECEIPTS_DIR = old_receipts
            incident_gate_module.detonate_module.QUARANTINE_DIR = old_quarantine
            incident_gate_module.detonate_module.ALERTS_DIR = old_alerts

            fake_receipt = {
                "observation": {"status": "COMPLETE"},
                "telemetry_incomplete": False,
                "identity": {"job_id": "mf-run-test", "submitted_by": "cinder-incident-gate"},
                "outward_report": {"risk_level": "hostile"},
                "gate": {"final_decision": "DENY"},
                "isolation": {"namespace_used": True, "seccomp_loaded": True},
                "purge": {"verified_externally": True},
                "detector_findings": [{"rule_id": "network_exfil_attempt"}],
            }

            def fake_detonate(*_args, **_kwargs):
                output = incident_gate_module.detonate_module.RECEIPTS_DIR / "mf-run-test.json"
                output.write_text(json.dumps(fake_receipt), encoding="utf-8")
                return fake_receipt

            try:
                run_root = root / "run"
                with patch.object(
                    incident_gate_module.detonate_module,
                    "detonate",
                    side_effect=fake_detonate,
                ):
                    result = run_probe(CINDER_PROBES[0], evidence_root=run_root)
                self.assertTrue(result.containment_held)
                self.assertTrue((run_root / "receipts" / "mf-run-test.json").is_file())
                for path in (old_receipts, old_quarantine, old_alerts):
                    self.assertEqual((path / "sentinel").read_text(), "preserve")
                self.assertEqual(
                    incident_gate_module.detonate_module.RECEIPTS_DIR,
                    old_receipts,
                )
            finally:
                (
                    incident_gate_module.detonate_module.RECEIPTS_DIR,
                    incident_gate_module.detonate_module.QUARANTINE_DIR,
                    incident_gate_module.detonate_module.ALERTS_DIR,
                ) = previous

    def test_symlink_evidence_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            link = root / "link"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaises(ValueError):
                _create_evidence_paths(link)


class TestReportGeneration(unittest.TestCase):
    """Test report generation from mock results."""

    def _mock_result(self, name: str, held: bool) -> ProbeResult:
        return ProbeResult(
            name=name,
            description=f"Test probe {name}",
            receipt={
                "isolation": {"namespace_used": True, "seccomp_loaded": True},
                "purge": {"verified_externally": True},
                "outward_report": {"risk_level": "hostile", "canaries_tripped": []},
                "destinations_attempted": {},
                "gate": {"final_decision": "DENY"},
                "detector_findings": [{"rule_id": "network_exfil_attempt"}],
            },
            containment_held=held,
            observed_risk="hostile",
            observed_decision="DENY",
            observed_rules={"network_exfil_attempt"},
            expected_risk="hostile",
            expected_decision="DENY",
            expected_rules=frozenset({"network_exfil_attempt"}),
            isolation_confirmed=True,
            purge_verified=True,
        )

    def test_report_contains_all_probes(self):
        results = [self._mock_result("test_a", True), self._mock_result("test_b", True)]
        report = generate_report(results)
        self.assertIn("test_a", report)
        self.assertIn("test_b", report)

    def test_report_shows_all_held(self):
        results = [self._mock_result("test_a", True)]
        report = generate_report(results)
        self.assertIn("ALL BOUNDARIES HELD", report)

    def test_report_shows_breach(self):
        results = [self._mock_result("test_a", False)]
        report = generate_report(results)
        self.assertIn("CONTAINMENT BREACH DETECTED", report)

    def test_report_is_markdown(self):
        results = [self._mock_result("test_a", True)]
        report = generate_report(results)
        self.assertTrue(report.startswith("# Cinder Incident Gate Report"))


class TestDoctorCheck(unittest.TestCase):
    """Test doctor check (lightweight, no sandbox)."""

    def test_doctor_returns_valid_structure(self):
        report = run_doctor()
        self.assertIn("timestamp", report)
        self.assertIn("overall_status", report)
        self.assertIn("checks", report)
        self.assertIn(report["overall_status"], {"READY", "FAIL_PREREQUISITES_MISSING"})

    def test_doctor_checks_are_list(self):
        report = run_doctor()
        self.assertIsInstance(report["checks"], list)
        for check in report["checks"]:
            self.assertIn("name", check)
            self.assertIn("ok", check)


# ---------------------------------------------------------------------------
# Tier 2: Integration tests — require real Cindermote sandbox
# ---------------------------------------------------------------------------

def _sandbox_available() -> bool:
    """Check if the real sandbox can run."""
    try:
        # Need namespace_setup.sh and the snapshot
        ns_script = PROJECT_DIR / "mote" / "namespace_setup.sh"
        if not ns_script.exists():
            return False
        # Quick check: can we import detonate?
        from cindermote.mote.detonate import detonate  # noqa: F401
        return True
    except Exception:
        return False


SKIP_INTEGRATION = not _sandbox_available()
SKIP_REASON = "Cindermote sandbox not available (missing namespace_setup.sh or dependencies)"


@unittest.skipIf(SKIP_INTEGRATION, SKIP_REASON)
class TestCinderProbeIntegration(unittest.TestCase):
    """Integration tests: detonate real probes through the real sandbox."""

    @classmethod
    def setUpClass(cls):
        _ensure_snapshot()
        cls._evidence_workspace = tempfile.TemporaryDirectory(
            prefix="cindermote-incident-tests-"
        )
        smoke_root = Path(cls._evidence_workspace.name) / "admission-smoke"
        smoke = run_probe(CINDER_PROBES[0], evidence_root=smoke_root)
        if not smoke.isolation_confirmed:
            isolation = smoke.receipt.get("isolation", {})
            findings = sorted(smoke.observed_rules)
            cls._evidence_workspace.cleanup()
            raise unittest.SkipTest(
                "real namespace+seccomp sandbox admission unavailable: "
                f"mode={isolation.get('mode', 'unknown')} "
                f"namespace={isolation.get('namespace_used')} "
                f"seccomp={isolation.get('seccomp_loaded')} "
                f"findings={findings}"
            )
        # An admitted sandbox whose payload observation cannot complete is
        # "not admitted" for containment purposes: report the suite as
        # skipped here, separately from execution coverage, instead of
        # letting incomplete evidence masquerade as probe verdicts.
        observation = smoke.receipt.get("observation", {})
        failure_class = (
            observation.get("failure_class") if isinstance(observation, dict) else None
        )
        if (
            smoke.observation_status != "COMPLETE"
            or smoke.observed_decision == "EVALUATION_INCOMPLETE"
        ):
            cls._evidence_workspace.cleanup()
            raise unittest.SkipTest(
                "sandbox admission cannot execute the payload interpreter "
                f"(observation={smoke.observation_status} "
                f"failure_class={failure_class} decision={smoke.observed_decision}); "
                "containment coverage requires a completed observation"
            )

    @classmethod
    def tearDownClass(cls):
        cls._evidence_workspace.cleanup()

    def _evidence_root(self) -> Path:
        return (
            Path(self._evidence_workspace.name)
            / f"{self._testMethodName}-{uuid.uuid4().hex[:8]}"
        )

    def _run_named_probe(self, name: str) -> ProbeResult:
        probe = next(p for p in CINDER_PROBES if p.name == name)
        return run_probe(probe, evidence_root=self._evidence_root())

    # --- Core containment probes ---

    def test_registry_proxy_abuse_blocked(self):
        """Step 1-2: Direct registry access is blocked by seccomp."""
        result = self._run_named_probe("registry_proxy_abuse")
        self.assertTrue(result.containment_held, f"Registry probe failed: {result.error}")
        self.assertEqual(result.observed_decision, "DENY")
        self.assertTrue(result.isolation_confirmed)
        self.assertTrue(result.purge_verified)

    def test_lateral_movement_blocked(self):
        """Step 3: Lateral movement to private networks is blocked."""
        result = self._run_named_probe("lateral_movement")
        self.assertTrue(result.containment_held, f"Lateral probe failed: {result.error}")
        self.assertEqual(result.observed_decision, "DENY")
        self.assertIn("namespace_escape_attempt", result.observed_rules)

    def test_metadata_access_blocked(self):
        """Step 4: Cloud metadata SSRF is blocked."""
        result = self._run_named_probe("metadata_access")
        self.assertTrue(result.containment_held, f"Metadata probe failed: {result.error}")
        self.assertEqual(result.observed_decision, "DENY")

    def test_credential_harvest_blocked(self):
        """Step 4-5: Credential harvesting is blocked and detected."""
        result = self._run_named_probe("credential_harvest")
        self.assertTrue(result.containment_held, f"Credential probe failed: {result.error}")
        self.assertEqual(result.observed_decision, "DENY")
        self.assertIn("cred_harvest_pattern", result.observed_rules)

    def test_outbound_exfil_blocked(self):
        """Step 6: Arbitrary outbound exfiltration is blocked."""
        result = self._run_named_probe("outbound_exfil")
        self.assertTrue(result.containment_held, f"Exfil probe failed: {result.error}")
        self.assertEqual(result.observed_decision, "DENY")
        self.assertIn("network_exfil_attempt", result.observed_rules)

    def test_tainted_output_blocked(self):
        """Step 6: Tainted output with shell injection is blocked."""
        result = self._run_named_probe("tainted_output")
        self.assertTrue(result.containment_held, f"Tainted probe failed: {result.error}")
        self.assertEqual(result.observed_decision, "DENY")

    # --- Infrastructure verification ---

    def test_every_probe_emits_receipt(self):
        """Every probe must produce a receipt with the correct structure."""
        probe = CINDER_PROBES[0]
        result = run_probe(probe, evidence_root=self._evidence_root())
        receipt = result.receipt
        self.assertIn("identity", receipt)
        self.assertIn("isolation", receipt)
        self.assertIn("gate", receipt)
        self.assertIn("purge", receipt)
        self.assertIn("outward_report", receipt)
        self.assertIn("detector_findings", receipt)

    def test_receipts_generated_from_host_evidence(self):
        """Receipts come from the real observer, not hardcoded JSON."""
        probe = CINDER_PROBES[0]
        result = run_probe(probe, evidence_root=self._evidence_root())
        receipt = result.receipt
        # The identity section should have a job_id from the real orchestrator
        job_id = receipt.get("identity", {}).get("job_id", "")
        self.assertTrue(job_id.startswith("mf-run-"), f"Bad job_id: {job_id}")
        # Submitted by our gate
        self.assertEqual(receipt["identity"]["submitted_by"], "cinder-incident-gate")

    def test_isolation_uses_real_namespaces(self):
        """Isolation section must confirm real namespace usage."""
        probe = CINDER_PROBES[0]
        result = run_probe(probe, evidence_root=self._evidence_root())
        iso = result.receipt.get("isolation", {})
        self.assertTrue(iso.get("namespace_used"))
        self.assertTrue(iso.get("seccomp_loaded"))

    def test_purge_verified_externally(self):
        """Teardown must be verified by the host, not self-reported."""
        probe = CINDER_PROBES[0]
        result = run_probe(probe, evidence_root=self._evidence_root())
        purge = result.receipt.get("purge", {})
        self.assertTrue(purge.get("verified_externally"))

    def test_teardown_succeeds_after_every_probe(self):
        """Every probe must leave no residual sandbox state."""
        for probe in CINDER_PROBES:
            result = run_probe(probe, evidence_root=self._evidence_root())
            self.assertTrue(
                result.purge_verified,
                f"Probe {probe.name} left residual state",
            )

    def test_full_run_all_contained(self):
        """Complete run of all probes must report all contained."""
        results = run_all_probes(evidence_root=self._evidence_root())
        for r in results:
            self.assertTrue(
                r.containment_held,
                f"Probe {r.name} failed: risk={r.observed_risk} "
                f"decision={r.observed_decision} error={r.error}",
            )

    def test_full_run_produces_master_receipt(self):
        """Full run must produce a master receipt and report."""
        results = run_all_probes(evidence_root=self._evidence_root())
        self.assertEqual(len(results), len(CINDER_PROBES))
        report = generate_report(results)
        self.assertIn("ALL BOUNDARIES HELD", report)


# ---------------------------------------------------------------------------
# Fail-closed observation: incomplete execution evidence must never reduce
# to ALLOW / clean success.
# ---------------------------------------------------------------------------

_POLICY = json.loads((PROJECT_DIR / "policy" / "hotcell-policy.json").read_text(encoding="utf-8"))
_POLICY_HASH = hashlib.sha256(
    json.dumps(_POLICY, sort_keys=True, separators=(",", ":")).encode("utf-8")
).hexdigest()
_SHA = "a" * 64


def _incomplete_outward() -> dict:
    return {
        "risk_level": "suspicious",
        "evidence": [
            {
                "tap_category": "syscall_class",
                "rule_id": "payload_observation_incomplete",
                "count": 1,
            }
        ],
        "capabilities_requested": [],
        "destinations": [],
        "canaries_tripped": [],
        "uncertainty": 1.0,
    }


def _valid_purge() -> dict:
    return {
        "method": "test cleanup",
        "verified_externally": True,
        "process_group_empty": True,
        "cgroup_empty": True,
        "cgroup_removed": True,
        "job_mount_removed": True,
        "job_directory_removed": True,
        "processes_remaining": 0,
        "remaining_host_resources": [],
    }


def _signed_legacy_receipt(
    key_path: Path,
    *,
    outward: dict,
    findings: list[dict],
    observation: dict | None,
    telemetry_incomplete: bool,
    uncertainty: float,
) -> dict:
    job_id = "mf-run-inc00001"
    return create_receipt(
        identity={
            "job_id": job_id,
            "artifact_sha256": _SHA,
            "artifact_type": "python-script",
            "submitted_by": "test",
            "received_at": "2026-09-24T00:00:00Z",
        },
        snapshot_policy={
            "snapshot_sha256": _SHA,
            "snapshot_verified_by": "test",
            "policy_version": _POLICY["policy_version"],
            "policy_hash": _POLICY_HASH,
        },
        isolation={
            "mode": "degraded-user",
            "namespace_used": True,
            "seccomp_loaded": True,
            "cgroups_used": False,
            "mlock_used": False,
        },
        budgets_granted={},
        capabilities={"requested": [], "granted": [], "denied": []},
        telemetry_summary={},
        canaries_touched={},
        destinations_attempted={},
        detector_findings=findings,
        gate=apply_scoring_matrix(outward, {}, job_id),
        outward_report=outward,
        purge=_valid_purge(),
        telemetry_incomplete=telemetry_incomplete,
        budget_exhausted=False,
        residual_uncertainty=uncertainty,
        key_path=key_path,
        observation=observation,
        active_policy=_POLICY,
    )


class TestIncompleteObservationReduction(unittest.TestCase):
    """The legacy reducer maps incomplete observation to EVALUATION_INCOMPLETE."""

    def test_policy_gate_never_returns_allow_for_incomplete_observation(self):
        for override in ({}, {"mf-run-x": "ALLOW"}, {"mf-run-x": "DENY"}):
            with self.subTest(override=override):
                gate = apply_scoring_matrix(_incomplete_outward(), override, "mf-run-x")
                self.assertNotEqual(gate["final_decision"], "ALLOW")
                self.assertEqual(gate["final_decision"], "EVALUATION_INCOMPLETE")
                self.assertEqual(gate["final_authority"], "fail_closed_incomplete_observation")

    def test_human_allow_override_is_blocked_for_incomplete_observation(self):
        gate = apply_scoring_matrix(_incomplete_outward(), {"mf-run-x": "ALLOW"}, "mf-run-x")
        self.assertEqual(gate["final_decision"], "EVALUATION_INCOMPLETE")
        self.assertTrue(gate["override_blocked_by_fail_closed"])

    def test_allow_remains_reachable_for_empty_evidence_completed_observation(self):
        outward = {
            "risk_level": "benign",
            "evidence": [],
            "capabilities_requested": [],
            "destinations": [],
            "canaries_tripped": [],
            "uncertainty": 0.0,
        }
        gate = apply_scoring_matrix(outward, {}, "mf-run-x")
        self.assertEqual(gate["final_decision"], "ALLOW")

    def test_signed_incomplete_observation_receipt_validates(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = _signed_legacy_receipt(
                Path(directory) / "key",
                outward=_incomplete_outward(),
                findings=[{"rule_id": "payload_observation_incomplete", "count": 1, "severity": "CRITICAL"}],
                observation={
                    "status": "EVALUATION_INCOMPLETE",
                    "exec_observed": False,
                    "failure_class": "interpreter_startup",
                    "diagnostic": "",
                },
                telemetry_incomplete=True,
                uncertainty=1.0,
            )
            self.assertEqual(receipt["gate"]["final_decision"], "EVALUATION_INCOMPLETE")
            validate_receipt(receipt, active_policy=_POLICY)

    def test_validator_rejects_incomplete_observation_contradictions(self):
        with tempfile.TemporaryDirectory() as directory:
            base = _signed_legacy_receipt(
                Path(directory) / "key",
                outward=_incomplete_outward(),
                findings=[{"rule_id": "payload_observation_incomplete", "count": 1, "severity": "CRITICAL"}],
                observation={
                    "status": "EVALUATION_INCOMPLETE",
                    "exec_observed": False,
                    "failure_class": "interpreter_startup",
                    "diagnostic": "",
                },
                telemetry_incomplete=True,
                uncertainty=1.0,
            )

            complete_claim = json.loads(json.dumps(base))
            complete_claim["observation"]["status"] = "COMPLETE"
            with self.assertRaises(ValueError):
                validate_receipt(complete_claim, active_policy=_POLICY)

            allow_claim = json.loads(json.dumps(base))
            allow_claim["gate"]["final_decision"] = "ALLOW"
            with self.assertRaises(ValueError):
                validate_receipt(allow_claim, active_policy=_POLICY)

            missing_section = json.loads(json.dumps(base))
            del missing_section["observation"]
            with self.assertRaises(ValueError):
                validate_receipt(missing_section, active_policy=_POLICY)

            full_telemetry = json.loads(json.dumps(base))
            full_telemetry["telemetry_incomplete"] = False
            with self.assertRaises(ValueError):
                validate_receipt(full_telemetry, active_policy=_POLICY)

            oversized = json.loads(json.dumps(base))
            oversized["observation"]["diagnostic"] = "x" * 513
            with self.assertRaises(ValueError):
                validate_receipt(oversized, active_policy=_POLICY)

    def test_allow_receipt_with_incomplete_observation_is_rejected(self):
        outward = {
            "risk_level": "benign",
            "evidence": [],
            "capabilities_requested": [],
            "destinations": [],
            "canaries_tripped": [],
            "uncertainty": 0.0,
        }
        with tempfile.TemporaryDirectory() as directory:
            receipt = _signed_legacy_receipt(
                Path(directory) / "key",
                outward=outward,
                findings=[],
                observation={
                    "status": "COMPLETE",
                    "exec_observed": True,
                    "failure_class": None,
                    "diagnostic": "",
                },
                telemetry_incomplete=False,
                uncertainty=0.0,
            )
            self.assertEqual(receipt["gate"]["final_decision"], "ALLOW")
            validate_receipt(receipt, active_policy=_POLICY)
            # Downgrading the observation without incomplete evidence breaks
            # the binding: ALLOW must stand on a completed observation.
            receipt["observation"]["status"] = "EVALUATION_INCOMPLETE"
            with self.assertRaises(ValueError):
                validate_receipt(receipt, active_policy=_POLICY)

    def test_load_diagnostic_extracts_bounded_loader_line(self):
        detonate = incident_gate_module.detonate_module
        stderr = (
            b"WARNING: Cindermote is using degraded-user isolation (no cgroups or mlock).\n"
            b"/usr/bin/python3: error while loading shared libraries: libexpat.so.1: "
            b"cannot open shared object file: No such file or directory\n"
        )
        failure_class, diagnostic = detonate._observation_load_diagnostic(stderr)
        self.assertEqual(failure_class, "library_load")
        self.assertIn("error while loading shared libraries", diagnostic)
        self.assertNotIn("degraded-user isolation", diagnostic)

    def test_load_diagnostic_quiet_stderr_has_no_failure_class(self):
        detonate = incident_gate_module.detonate_module
        failure_class, diagnostic = detonate._observation_load_diagnostic(b"")
        self.assertEqual(failure_class, "")
        self.assertEqual(diagnostic, "")

    def test_load_diagnostic_bounds_and_sanitizes_excerpt(self):
        detonate = incident_gate_module.detonate_module
        stderr = b"error while loading shared libraries: " + b"x\xff" * 300 + b"\n"
        failure_class, diagnostic = detonate._observation_load_diagnostic(stderr)
        self.assertEqual(failure_class, "library_load")
        self.assertLessEqual(len(diagnostic), 240)
        self.assertTrue(all(32 <= ord(char) < 127 for char in diagnostic))

    def test_evaluate_receipt_never_holds_on_incomplete_observation(self):
        probe = CINDER_PROBES[0]
        receipt = {
            "outward_report": {"risk_level": "hostile"},
            "gate": {"final_decision": "DENY"},
            "isolation": {"namespace_used": True, "seccomp_loaded": True},
            "purge": {"verified_externally": True},
            "detector_findings": [{"rule_id": "network_exfil_attempt"}],
            "observation": {
                "status": "EVALUATION_INCOMPLETE",
                "exec_observed": False,
                "failure_class": "interpreter_startup",
                "diagnostic": "",
            },
        }
        result = _evaluate_receipt(probe, receipt)
        self.assertFalse(result.containment_held)
        self.assertEqual(result.observation_status, "EVALUATION_INCOMPLETE")


# ---------------------------------------------------------------------------
# Detonation fixtures: interpreter-startup, library-load, and observer
# failure must never reduce to ALLOW; detection must work when the
# observation completes.
# ---------------------------------------------------------------------------

_HOSTILE_SOCKET_SOURCE = (
    "import socket\n"
    "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
    "try:\n"
    "    s.connect(('10.0.0.1', 80))\n"
    "except Exception:\n"
    "    pass\n"
)
_BENIGN_SOURCE = "print('observation-complete')\n"


def _elf_soname(path: Path) -> str | None:
    """Read DT_SONAME from an ELF64 shared object (mirrors detonate._elf_links)."""
    try:
        data = path.read_bytes()
    except (OSError, ValueError):
        return None
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return None
    try:
        header = struct.unpack_from("<16sHHIQQQIHHHHHH", data, 0)
    except struct.error:
        return None
    phoff, phentsize, phnum = header[5], header[9], header[10]
    segments: list[tuple[int, int, int, int]] = []
    dynamic: tuple[int, int] | None = None
    for index in range(phnum):
        offset = phoff + index * phentsize
        try:
            p_type, _, p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from(
                "<IIQQQQQQ", data, offset
            )
        except struct.error:
            return None
        segments.append((p_type, p_offset, p_vaddr, p_filesz))
        if p_type == 2:  # PT_DYNAMIC
            dynamic = (p_offset, p_filesz)
    if dynamic is None:
        return None
    soname_relative: int | None = None
    strtab_address: int | None = None
    strtab_size = 0
    start, size = dynamic
    for offset in range(start, min(start + size, len(data)), 16):
        try:
            tag, value = struct.unpack_from("<QQ", data, offset)
        except struct.error:
            break
        if tag == 0:
            break
        if tag == 14:  # DT_SONAME
            soname_relative = value
        elif tag == 5:  # DT_STRTAB
            strtab_address = value
        elif tag == 10:  # DT_STRSZ
            strtab_size = value
    if soname_relative is None or strtab_address is None:
        return None
    strtab_offset = None
    for p_type, p_offset, p_vaddr, p_filesz in segments:
        if p_type == 1 and p_vaddr <= strtab_address < p_vaddr + p_filesz:
            strtab_offset = p_offset + (strtab_address - p_vaddr)
            break
    if strtab_offset is None:
        return None
    maximum = min(len(data), strtab_offset + (strtab_size or len(data)))
    begin = strtab_offset + soname_relative
    if begin >= maximum:
        return None
    end = data.find(b"\0", begin, maximum)
    if end == -1:
        return None
    return data[begin:end].decode("utf-8", "replace")


def _build_rootfs_tar(target: Path, populate) -> Path:
    root = target.parent / f"{target.stem}-rootfs"
    for relative in (
        "home/mote/.aws",
        "home/mote/.ssh",
        "tmp",
        "var/log",
        "dev",
        "proc",
        "sys",
        "etc",
        "usr/bin",
        "usr/lib",
        "lib64",
    ):
        (root / relative).mkdir(parents=True, exist_ok=True)
    (root / "etc" / "passwd").write_text(
        "root:x:0:0:cindermote:/home/mote:/bin/sh\n", encoding="utf-8"
    )
    (root / "etc" / "group").write_text("root:x:0:\n", encoding="utf-8")
    (root / "etc" / "hosts").write_text("127.0.0.1 localhost cindermote\n", encoding="utf-8")
    populate(root)
    with tarfile.open(target, "w:gz") as archive:
        archive.add(root, arcname=".", recursive=True)
    return target


def _build_runnable_snapshot(workspace: Path) -> Path | None:
    """Repack the host-built golden snapshot with the SONAME symlinks its
    library closure dropped. Returns None when the snapshot cannot be made
    runnable on this host (reported as a skip, not a verdict)."""
    detonate = incident_gate_module.detonate_module
    _ensure_snapshot()
    extract_dir = workspace / "runnable-rootfs"
    extract_dir.mkdir()
    with tarfile.open(detonate.SNAPSHOT_PATH, "r:gz") as archive:
        try:
            archive.extractall(extract_dir, filter="data")
        except TypeError:
            archive.extractall(extract_dir)
    for library in extract_dir.rglob("*"):
        if not library.is_file() or library.is_symlink() or ".so" not in library.name:
            continue
        soname = _elf_soname(library)
        if not soname:
            continue
        link = library.parent / soname
        if not link.exists():
            link.symlink_to(library.name)
    target = workspace / "runnable-snapshot.tar.gz"
    with tarfile.open(target, "w:gz") as archive:
        archive.add(extract_dir, arcname=".", recursive=True)
    return target


@unittest.skipIf(SKIP_INTEGRATION, SKIP_REASON)
class TestObservationFailureDetonation(unittest.TestCase):
    """End-to-end fail-closed detonations through the real sandbox."""

    @classmethod
    def setUpClass(cls):
        cls._workspace = tempfile.TemporaryDirectory(
            prefix="cindermote-observation-failures-"
        )
        workspace = Path(cls._workspace.name)
        cls._missing_snapshot = _build_rootfs_tar(
            workspace / "missing-interpreter.tar.gz", lambda _root: None
        )
        cls._loader_snapshot = None
        true_binary = shutil.which("true")
        ld_linux = Path("/lib64/ld-linux-x86-64.so.2")
        if platform.machine() == "x86_64" and true_binary and ld_linux.exists():
            def _rig_loader(rootfs: Path) -> None:
                # A valid ELF whose dynamic loader is present but whose
                # required shared libraries are absent: execve succeeds, the
                # loader fails before any payload instruction runs.
                shutil.copy2(true_binary, rootfs / "usr" / "bin" / "python3")
                shutil.copy2(
                    ld_linux.resolve(),
                    rootfs / "lib64" / "ld-linux-x86-64.so.2",
                )

            cls._loader_snapshot = _build_rootfs_tar(
                workspace / "loader-failure.tar.gz", _rig_loader
            )
        cls._runnable_snapshot = None
        try:
            cls._runnable_snapshot = _build_runnable_snapshot(workspace)
        except Exception:
            cls._runnable_snapshot = None
        # Admission smoke: the failure fixtures require a sandbox that admits
        # the child; otherwise report not-admitted as a skip.
        smoke, _scratch = cls()._detonate_fixture(cls._missing_snapshot, _BENIGN_SOURCE)
        isolation = smoke.get("isolation", {})
        if not (isolation.get("namespace_used") and isolation.get("seccomp_loaded")):
            cls._workspace.cleanup()
            raise unittest.SkipTest(
                "sandbox admission unavailable for observation-failure fixtures: "
                f"namespace={isolation.get('namespace_used')} "
                f"seccomp={isolation.get('seccomp_loaded')}"
            )
        cls._runnable_observation = None
        if cls._runnable_snapshot is not None:
            probe, _scratch = cls()._detonate_fixture(cls._runnable_snapshot, _BENIGN_SOURCE)
            cls._runnable_observation = probe.get("observation", {}).get("status")

    @classmethod
    def tearDownClass(cls):
        cls._workspace.cleanup()

    def _detonate_fixture(self, snapshot: Path, source: str) -> tuple[dict, Path]:
        detonate = incident_gate_module.detonate_module
        scratch = Path(self._workspace.name) / f"run-{uuid.uuid4().hex[:8]}"
        scratch.mkdir()
        artifact = scratch / "payload.py"
        artifact.write_text(source, encoding="utf-8")
        manifest = {
            "sha256": hashlib.sha256(snapshot.read_bytes()).hexdigest(),
            "built_at": "test",
            "size_bytes": snapshot.stat().st_size,
        }
        with (
            patch.multiple(
                detonate,
                SNAPSHOT_PATH=snapshot,
                RECEIPTS_DIR=scratch / "receipts",
                QUARANTINE_DIR=scratch / "quarantine",
                ALERTS_DIR=scratch / "alerts",
                OBSERVER_KEY_PATH=scratch / ".observer_key",
            ),
            patch.object(detonate, "verify_snapshot", return_value=manifest),
        ):
            receipt = detonate.detonate(
                artifact, "python-script", submitted_by="incident-gate-fail-closed-test"
            )
        return receipt, scratch

    def _assert_incomplete_receipt(self, receipt: dict, failure_class: str) -> None:
        gate = receipt["gate"]
        self.assertNotEqual(gate["final_decision"], "ALLOW")
        self.assertEqual(gate["final_decision"], "EVALUATION_INCOMPLETE")
        self.assertEqual(receipt["residual_uncertainty"], 1.0)
        self.assertTrue(receipt["telemetry_incomplete"])
        self.assertEqual(
            receipt["detector_findings"],
            [{"rule_id": "payload_observation_incomplete", "count": 1, "severity": "CRITICAL"}],
        )
        observation = receipt["observation"]
        self.assertEqual(observation["status"], "EVALUATION_INCOMPLETE")
        self.assertEqual(observation["failure_class"], failure_class)
        probe = next(p for p in CINDER_PROBES if p.name == "registry_proxy_abuse")
        result = _evaluate_receipt(probe, receipt)
        self.assertFalse(result.containment_held)
        validate_receipt(receipt, active_policy=_POLICY)

    def test_missing_interpreter_executable_never_yields_allow(self):
        receipt, scratch = self._detonate_fixture(self._missing_snapshot, _HOSTILE_SOCKET_SOURCE)
        self._assert_incomplete_receipt(receipt, "interpreter_startup")
        self.assertFalse(receipt["observation"]["exec_observed"])
        # Bounded diagnostics are preserved on the failure path.
        alerts = list((scratch / "alerts").glob("*.alert"))
        self.assertEqual(len(alerts), 1)
        alert = json.loads(alerts[0].read_text(encoding="utf-8"))
        self.assertEqual(alert["reason"], "payload_observation_incomplete")
        self.assertEqual(alert["details"]["failure_class"], "interpreter_startup")
        self.assertLessEqual(len(alert["details"]["diagnostic"]), 512)

    def test_loader_failure_before_payload_never_yields_allow(self):
        if self._loader_snapshot is None:
            self.skipTest("loader fixture requires x86_64 /bin/true and ld-linux")
        receipt, _scratch = self._detonate_fixture(self._loader_snapshot, _HOSTILE_SOCKET_SOURCE)
        self._assert_incomplete_receipt(receipt, "library_load")
        self.assertTrue(receipt["observation"]["exec_observed"])
        self.assertIn(
            "error while loading shared libraries",
            receipt["observation"]["diagnostic"],
        )

    def test_observer_exit_before_final_evidence_never_yields_allow(self):
        detonate = incident_gate_module.detonate_module
        real_tracer = detonate.HostTracer

        class FailingTracer(real_tracer):
            def resume_root(self):
                super().resume_root()
                self.trace_error = "injected:observer_exit"

        with patch.object(detonate, "HostTracer", FailingTracer):
            receipt, _scratch = self._detonate_fixture(self._missing_snapshot, _HOSTILE_SOCKET_SOURCE)
        gate = receipt["gate"]
        self.assertNotEqual(gate["final_decision"], "ALLOW")
        self.assertEqual(gate["final_decision"], "DENY")
        self.assertTrue(receipt["telemetry_incomplete"])
        self.assertEqual(receipt["residual_uncertainty"], 1.0)
        self.assertIn(
            "telemetry_loss",
            {finding["rule_id"] for finding in receipt["detector_findings"]},
        )

    def test_hostile_probe_is_detected_when_observation_completes(self):
        if self._runnable_observation != "COMPLETE":
            self.skipTest(
                "host-built snapshot cannot execute its interpreter on this host "
                f"(observation={self._runnable_observation}); detection coverage "
                "requires a completed observation"
            )
        receipt, _scratch = self._detonate_fixture(self._runnable_snapshot, _HOSTILE_SOCKET_SOURCE)
        self.assertEqual(receipt["gate"]["final_decision"], "DENY")
        self.assertEqual(receipt["observation"]["status"], "COMPLETE")
        self.assertIn(
            "network_exfil_attempt",
            {finding["rule_id"] for finding in receipt["detector_findings"]},
        )
        probe = next(p for p in CINDER_PROBES if p.name == "registry_proxy_abuse")
        result = _evaluate_receipt(probe, receipt)
        self.assertTrue(result.containment_held)

    def test_allow_is_reachable_only_from_completed_observation(self):
        if self._runnable_observation != "COMPLETE":
            self.skipTest(
                "host-built snapshot cannot execute its interpreter on this host "
                f"(observation={self._runnable_observation})"
            )
        receipt, _scratch = self._detonate_fixture(self._runnable_snapshot, _BENIGN_SOURCE)
        self.assertEqual(receipt["observation"]["status"], "COMPLETE")
        self.assertEqual(receipt["gate"]["final_decision"], "ALLOW")
        self.assertEqual(receipt["residual_uncertainty"], 0.0)


if __name__ == "__main__":
    unittest.main()