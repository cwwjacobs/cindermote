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

import json
import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

import cindermote.incident_gate as incident_gate_module
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


if __name__ == "__main__":
    unittest.main()
