from __future__ import annotations

import argparse
import copy
import errno
import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from cindermote.gate.policy_gate import apply_scoring_matrix
from cindermote.mote import detonate as detonate_module
from cindermote.mote.detonate import (
    CgroupOperationError,
    ControlMessage,
    ProcessIdentity,
    READINESS_PROTOCOL,
    SandboxIdentityError,
    _cleanup_legacy_resources,
    _inspect_sandbox_identity,
    _isolation_admission_failures,
    _join_cgroup,
    _process_group_members,
    _read_control,
    _sandbox_child,
    _validate_tracer_target,
    _write_control,
)
from cindermote.observer.detectors import DetectorEngine
from cindermote.observer.ptracer import HostTracer, WAIT_WALL
from cindermote.observer.receipt import (
    create_receipt,
    required_isolation_controls,
    validate_receipt,
)


SHA = "a" * 64
POLICY_PATH = Path(__file__).resolve().parents[1] / "policy" / "hotcell-policy.json"
POLICY = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
POLICY_HASH = hashlib.sha256(
    json.dumps(POLICY, sort_keys=True, separators=(",", ":")).encode("utf-8")
).hexdigest()


def _policy_hash(policy: dict) -> str:
    return hashlib.sha256(
        json.dumps(policy, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


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


def _valid_legacy_receipt() -> dict:
    outward_report = {
        "risk_level": "benign",
        "evidence": [],
        "capabilities_requested": [],
        "destinations": [],
        "canaries_tripped": [],
        "uncertainty": 0.0,
    }
    job_id = "mf-run-1234abcd"
    return {
        "identity": {
            "job_id": job_id,
            "artifact_sha256": SHA,
            "artifact_type": "python-script",
            "submitted_by": "test",
            "received_at": "2026-07-16T00:00:00Z",
        },
        "snapshot_policy": {
            "snapshot_sha256": SHA,
            "snapshot_verified_by": "test",
            "policy_version": POLICY["policy_version"],
            "policy_hash": POLICY_HASH,
        },
        "isolation": {
            "mode": "full-root",
            "namespace_used": True,
            "seccomp_loaded": True,
            "cgroups_used": True,
            "mlock_used": True,
        },
        "budgets_granted": {},
        "capabilities": {"requested": [], "granted": [], "denied": []},
        "telemetry_summary": {},
        "canaries_touched": {},
        "destinations_attempted": {},
        "detector_findings": [],
        "gate": apply_scoring_matrix(outward_report, {}, job_id),
        "outward_report": outward_report,
        "purge": _valid_purge(),
        "telemetry_incomplete": False,
        "budget_exhausted": False,
        "residual_uncertainty": 0.0,
        "receipt_signature": SHA,
    }


def _set_failed_purge(receipt: dict, *, include_finding: bool) -> None:
    receipt["purge"].update(
        {
            "verified_externally": False,
            "job_directory_removed": False,
            "remaining_host_resources": ["job_directory:/tmp/cindermote/test"],
        }
    )
    receipt["telemetry_incomplete"] = True
    receipt["residual_uncertainty"] = 1.0
    receipt["outward_report"]["uncertainty"] = 1.0
    if include_finding:
        receipt["detector_findings"] = [
            {"rule_id": "purge_failure", "count": 1, "severity": "CRITICAL"}
        ]
        receipt["outward_report"].update(
            {
                "risk_level": "hostile",
                "evidence": [
                    {
                        "tap_category": "syscall_class",
                        "rule_id": "purge_failure",
                        "count": 1,
                    }
                ],
            }
        )
        receipt["gate"] = apply_scoring_matrix(
            receipt["outward_report"], {}, receipt["identity"]["job_id"]
        )


def _set_failed_isolation(receipt: dict, control: str, *, human_allow: bool = False) -> None:
    receipt["isolation"][control] = False
    receipt["telemetry_incomplete"] = True
    receipt["residual_uncertainty"] = 1.0
    receipt["detector_findings"] = [
        {
            "rule_id": "isolation_admission_failure",
            "count": 1,
            "severity": "CRITICAL",
        }
    ]
    receipt["outward_report"].update(
        {
            "risk_level": "hostile",
            "uncertainty": 1.0,
            "evidence": [
                {
                    "tap_category": "syscall_class",
                    "rule_id": "isolation_admission_failure",
                    "count": 1,
                }
            ],
        }
    )
    override = (
        {receipt["identity"]["job_id"]: "ALLOW"}
        if human_allow
        else {}
    )
    receipt["gate"] = apply_scoring_matrix(
        receipt["outward_report"], override, receipt["identity"]["job_id"]
    )


def _force_autonomous_allow(receipt: dict) -> None:
    receipt["gate"] = {
        "policy_gate_decision": "ALLOW",
        "policy_gate_reason": "no_anomaly_detected",
        "human_gate_override": "none",
        "final_decision": "ALLOW",
        "final_authority": "policy_gate_autonomous",
        "override_blocked_by_fail_closed": False,
    }


class LegacySecurityRepairTests(unittest.TestCase):
    def test_complete_legacy_receipt_is_accepted(self) -> None:
        validate_receipt(_valid_legacy_receipt())

    def test_validation_rejects_allow_when_purge_is_unverified(self) -> None:
        receipt = _valid_legacy_receipt()
        _set_failed_purge(receipt, include_finding=True)
        _force_autonomous_allow(receipt)
        with self.assertRaises(ValueError):
            validate_receipt(receipt)

    def test_construction_rejects_allow_when_purge_is_unverified(self) -> None:
        receipt = _valid_legacy_receipt()
        _set_failed_purge(receipt, include_finding=True)
        _force_autonomous_allow(receipt)
        with tempfile.TemporaryDirectory() as temporary, self.assertRaises(ValueError):
            create_receipt(
                identity=copy.deepcopy(receipt["identity"]),
                snapshot_policy=copy.deepcopy(receipt["snapshot_policy"]),
                isolation=copy.deepcopy(receipt["isolation"]),
                budgets_granted={},
                capabilities=copy.deepcopy(receipt["capabilities"]),
                telemetry_summary={},
                canaries_touched={},
                destinations_attempted={},
                detector_findings=copy.deepcopy(receipt["detector_findings"]),
                gate=copy.deepcopy(receipt["gate"]),
                outward_report=copy.deepcopy(receipt["outward_report"]),
                purge=copy.deepcopy(receipt["purge"]),
                telemetry_incomplete=True,
                budget_exhausted=False,
                residual_uncertainty=1.0,
                key_path=Path(temporary) / "observer.key",
                active_policy=POLICY,
            )

    def test_consistent_failed_purge_receipt_is_denied_and_valid(self) -> None:
        receipt = _valid_legacy_receipt()
        _set_failed_purge(receipt, include_finding=True)
        validate_receipt(receipt)
        self.assertEqual(receipt["gate"]["final_decision"], "DENY")
        self.assertEqual(receipt["gate"]["final_authority"], "fail_closed_infrastructure_gate")

    def test_full_root_required_cgroup_failure_is_not_admitted(self) -> None:
        required = required_isolation_controls("full-root", POLICY)
        controls = {
            "namespace_used": True,
            "seccomp_loaded": True,
            "cgroups_used": False,
            "mlock_used": True,
        }
        self.assertEqual(
            _isolation_admission_failures(True, controls, required),
            ["cgroups_used"],
        )

    def test_cgroup_setup_failure_never_begins_traced_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "artifact.py"
            artifact.write_text("pass\n", encoding="utf-8")
            with (
                mock.patch.object(detonate_module.os, "geteuid", return_value=0),
                mock.patch.object(
                    detonate_module,
                    "verify_snapshot",
                    return_value={"sha256": SHA},
                ),
                mock.patch.object(
                    detonate_module,
                    "_setup_cgroup",
                    side_effect=CgroupOperationError(
                        "write_cpu_max",
                        OSError(errno.EIO, "test failure"),
                    ),
                ),
                mock.patch.object(detonate_module.subprocess, "Popen") as popen,
                mock.patch.object(detonate_module, "_write_alert") as alert,
                mock.patch.object(detonate_module, "_mark_host_state"),
                mock.patch.object(
                    detonate_module,
                    "create_receipt",
                    return_value={"created": True},
                ) as create,
                mock.patch.object(detonate_module, "write_receipt"),
            ):
                result = detonate_module.detonate(artifact, "python-script", POLICY)

        self.assertEqual(result, {"created": True})
        popen.assert_not_called()
        receipt_inputs = create.call_args.kwargs
        self.assertIs(receipt_inputs["isolation"]["cgroups_used"], False)
        self.assertEqual(receipt_inputs["gate"]["final_decision"], "DENY")
        self.assertIn(
            "isolation_admission_failure",
            {finding["rule_id"] for finding in receipt_inputs["detector_findings"]},
        )
        alert_details = alert.call_args.args[2]
        self.assertEqual(
            alert_details["diagnostic"]["cgroup"],
            {"stage": "write_cpu_max", "errno": errno.EIO},
        )

    def test_cgroup_setup_diagnostic_is_bound_to_a_valid_denial_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "artifact.py"
            artifact.write_text("pass\n", encoding="utf-8")
            alerts = root / "alerts"
            receipts = root / "receipts"
            with (
                mock.patch.object(detonate_module.os, "geteuid", return_value=0),
                mock.patch.object(detonate_module, "verify_snapshot", return_value={"sha256": SHA}),
                mock.patch.object(
                    detonate_module,
                    "_setup_cgroup",
                    side_effect=CgroupOperationError(
                        "write_memory_max",
                        OSError(errno.EACCES, "sensitive detail is not emitted"),
                    ),
                ),
                mock.patch.object(detonate_module, "ALERTS_DIR", alerts),
                mock.patch.object(detonate_module, "RECEIPTS_DIR", receipts),
                mock.patch.object(detonate_module, "OBSERVER_KEY_PATH", root / "observer.key"),
                mock.patch.object(detonate_module, "LEGACY_CGROUP_ROOT", root / "cgroups"),
            ):
                receipt = detonate_module.detonate(artifact, "python-script", POLICY)

            validate_receipt(receipt, active_policy=POLICY)
            self.assertEqual(receipt["gate"]["final_decision"], "DENY")
            alert = json.loads(next(alerts.glob("*.alert")).read_text(encoding="utf-8"))
            self.assertEqual(
                alert["details"]["diagnostic"]["cgroup"],
                {"stage": "write_memory_max", "errno": errno.EACCES},
            )
            self.assertNotIn("sensitive detail", json.dumps(alert))

    def test_cgroup_join_failure_is_a_pre_execution_denial(self) -> None:
        class FakeProcess:
            pid = 99_999_998

            def __init__(self) -> None:
                self.stdin = tempfile.TemporaryFile()
                self.stdout = tempfile.TemporaryFile()
                self.stderr = tempfile.TemporaryFile()

            def poll(self) -> int:
                return 0

        process = FakeProcess()
        wrapper = ProcessIdentity(
            process.pid,
            "S",
            1,
            process.pid,
            process.pid,
            1001,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "artifact.py"
            artifact.write_text("pass\n", encoding="utf-8")
            cgroup = root / "cgroup"
            with (
                mock.patch.object(detonate_module.os, "geteuid", return_value=0),
                mock.patch.object(detonate_module, "verify_snapshot", return_value={"sha256": SHA}),
                mock.patch.object(
                    detonate_module,
                    "_setup_cgroup",
                    return_value=cgroup,
                ),
                mock.patch.object(
                    detonate_module.subprocess,
                    "Popen",
                    return_value=process,
                ),
                mock.patch.object(
                    detonate_module,
                    "_read_process_identity",
                    return_value=wrapper,
                ),
                mock.patch.object(
                    detonate_module,
                    "_join_cgroup",
                    side_effect=CgroupOperationError(
                        "join_wrapper",
                        OSError(errno.EPERM, "test denial"),
                    ),
                ),
                mock.patch.object(detonate_module, "HostTracer") as tracer,
                mock.patch.object(detonate_module, "_write_alert") as alert,
                mock.patch.object(detonate_module, "_mark_host_state"),
                mock.patch.object(
                    detonate_module,
                    "create_receipt",
                    return_value={"created": True},
                ) as create,
                mock.patch.object(detonate_module, "write_receipt"),
            ):
                result = detonate_module.detonate(artifact, "python-script", POLICY)

        self.assertEqual(result, {"created": True})
        tracer.assert_not_called()
        self.assertEqual(create.call_args.kwargs["gate"]["final_decision"], "DENY")
        self.assertEqual(
            alert.call_args.args[2]["diagnostic"]["cgroup"],
            {"stage": "join_wrapper", "errno": errno.EPERM},
        )

    @staticmethod
    def _ready_message(
        *,
        claimed_pid: int = 101,
        sender_pid: int = 101,
        start_time_ticks: int = 2001,
    ) -> ControlMessage:
        return ControlMessage(
            {
                "ready": True,
                "namespace_used": True,
                "seccomp_loaded": True,
                "overlay_used": True,
                "mlock_used": True,
                "device_bind_used": True,
                "canaries": {},
                "identity": {
                    "protocol": READINESS_PROTOCOL,
                    "host_pid": claimed_pid,
                    "start_time_ticks": start_time_ticks,
                },
            },
            sender_pid,
            0,
            0,
            True,
        )

    @staticmethod
    def _wrapper_identity(*, state: str = "S") -> ProcessIdentity:
        return ProcessIdentity(100, state, 1, 100, 100, 1001)

    @staticmethod
    def _child_identity(
        *,
        state: str = "T",
        parent_pid: int = 100,
    ) -> ProcessIdentity:
        return ProcessIdentity(101, state, parent_pid, 100, 100, 2001)

    def _inspect_with_evidence(
        self,
        *,
        message: ControlMessage | None = None,
        wrapper_current: ProcessIdentity | None = None,
        child: ProcessIdentity | None = None,
        members: list[int] | None = None,
        require_stopped: bool = True,
    ):
        wrapper = self._wrapper_identity()
        identities = {
            100: wrapper_current if wrapper_current is not None else wrapper,
            101: child if child is not None else self._child_identity(),
        }
        with (
            mock.patch.object(
                detonate_module,
                "_read_process_identity",
                side_effect=lambda pid: identities.get(pid),
            ),
            mock.patch.object(
                detonate_module,
                "_cgroup_members",
                return_value=(members if members is not None else [100, 101], True),
            ),
            mock.patch.object(detonate_module.os, "pidfd_open", return_value=77),
        ):
            return _inspect_sandbox_identity(
                message if message is not None else self._ready_message(),
                wrapper,
                Path("/sys/fs/cgroup/cindermote/mf-run-test"),
                full_root=True,
                require_stopped=require_stopped,
            )

    def test_validated_child_identity_binds_pid_ancestry_group_session_and_cgroup(self) -> None:
        admission = self._inspect_with_evidence()
        self.assertEqual(admission.pid, 101)
        self.assertEqual(admission.start_time_ticks, 2001)
        admission.pidfd = -1

    def test_forged_readiness_pid_is_rejected(self) -> None:
        with self.assertRaisesRegex(SandboxIdentityError, "readiness_pid_mismatch"):
            self._inspect_with_evidence(
                message=self._ready_message(claimed_pid=102, sender_pid=101)
            )

    def test_unrelated_stopped_pid_is_rejected(self) -> None:
        with self.assertRaisesRegex(SandboxIdentityError, "sandbox_ancestry_mismatch"):
            self._inspect_with_evidence(
                child=self._child_identity(parent_pid=999),
            )

    def test_child_outside_exact_cgroup_is_rejected(self) -> None:
        with self.assertRaisesRegex(SandboxIdentityError, "sandbox_cgroup_mismatch"):
            self._inspect_with_evidence(members=[100])

    def test_unstopped_child_is_rejected(self) -> None:
        with self.assertRaisesRegex(SandboxIdentityError, "sandbox_not_stopped"):
            self._inspect_with_evidence(child=self._child_identity(state="S"))

    def test_wrapper_exit_before_validation_is_rejected(self) -> None:
        with self.assertRaisesRegex(SandboxIdentityError, "wrapper_exited"):
            self._inspect_with_evidence(
                wrapper_current=self._wrapper_identity(state="Z"),
            )

    def test_missing_readiness_identity_is_rejected(self) -> None:
        message = self._ready_message()
        message.status.pop("identity")
        with self.assertRaisesRegex(SandboxIdentityError, "readiness_identity_malformed"):
            self._inspect_with_evidence(message=message)

    def test_absent_readiness_message_is_rejected(self) -> None:
        with self.assertRaisesRegex(SandboxIdentityError, "readiness_absent"):
            _inspect_sandbox_identity(
                None,
                self._wrapper_identity(),
                Path("/sys/fs/cgroup/cindermote/mf-run-test"),
                full_root=True,
                require_stopped=True,
            )

    def test_kernel_sender_credentials_are_bound_to_control_message(self) -> None:
        control_host, control_child = socket.socketpair(
            socket.AF_UNIX,
            socket.SOCK_SEQPACKET,
        )
        control_host.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        try:
            _write_control(control_child.fileno(), {"ready": False})
            message = _read_control(control_host)
        finally:
            control_host.close()
            control_child.close()
        self.assertIsNotNone(message)
        self.assertTrue(message.credentials_valid)
        self.assertEqual(message.sender_pid, os.getpid())

    def test_cgroup_join_failure_preserves_stage_and_errno(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            group = Path(temporary)
            with mock.patch.object(
                Path,
                "write_text",
                side_effect=OSError(errno.EPERM, "test denial"),
            ):
                with self.assertRaises(CgroupOperationError) as raised:
                    _join_cgroup(group, 123)
        self.assertEqual(
            raised.exception.evidence(),
            {"stage": "join_wrapper", "errno": errno.EPERM},
        )

    def test_host_tracer_attaches_to_selected_stopped_pid(self) -> None:
        process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import os, signal; os.kill(os.getpid(), signal.SIGSTOP); os._exit(0)",
            ],
            start_new_session=True,
        )
        tracer = HostTracer(process.pid, DetectorEngine())
        try:
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                identity = detonate_module._read_process_identity(process.pid)
                if identity is not None and identity.state in {"T", "t"}:
                    break
                time.sleep(0.005)
            else:
                self.fail("trace target did not stop")
            tracer.attach()
            self.assertEqual(tracer.root_pid, process.pid)
            tracer.resume_root()
            deadline = time.monotonic() + 2.0
            while tracer.active_pids and time.monotonic() < deadline:
                try:
                    waited_pid, status = os.waitpid(-1, os.WNOHANG | WAIT_WALL)
                except ChildProcessError:
                    tracer.active_pids.clear()
                    break
                if waited_pid > 0:
                    tracer.process_wait_status(waited_pid, status)
                else:
                    time.sleep(0.005)
            self.assertFalse(tracer.active_pids)
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                process.wait(timeout=2)
            except (ChildProcessError, subprocess.TimeoutExpired):
                pass

    def test_tracer_target_must_equal_validated_sandbox_child(self) -> None:
        admission = detonate_module.SandboxAdmission(101, 2001, -1)
        tracer = mock.Mock(root_pid=102)
        with self.assertRaisesRegex(SandboxIdentityError, "tracer_pid_mismatch"):
            _validate_tracer_target(tracer, admission)

    @unittest.skipUnless(os.geteuid() == 0 and os.access("/sys/fs/cgroup", os.W_OK), "requires root and writable cgroup v2")
    def test_privileged_benign_traces_validated_child_inside_exact_cgroup(self) -> None:
        observed: dict[str, object] = {}
        original_join = detonate_module._join_cgroup
        original_inspect = detonate_module._inspect_sandbox_identity
        original_tracer = detonate_module.HostTracer

        def recording_join(group: Path, pid: int) -> None:
            original_join(group, pid)
            observed["group"] = group
            observed["wrapper_pid"] = pid

        def recording_inspect(*args: object, **kwargs: object):
            admission = original_inspect(*args, **kwargs)
            group = args[2]
            members, known = detonate_module._cgroup_members(group)
            observed["child_pid"] = admission.pid
            observed["members_known"] = known
            observed["members"] = members
            return admission

        class RecordingTracer(original_tracer):
            def __init__(self, root_pid: int, *args: object, **kwargs: object) -> None:
                observed["traced_pid"] = root_pid
                super().__init__(root_pid, *args, **kwargs)

        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "benign.py"
            artifact.write_text('print("hello world")\n', encoding="utf-8")
            with (
                mock.patch.object(detonate_module, "_join_cgroup", side_effect=recording_join),
                mock.patch.object(
                    detonate_module,
                    "_inspect_sandbox_identity",
                    side_effect=recording_inspect,
                ),
                mock.patch.object(detonate_module, "HostTracer", RecordingTracer),
            ):
                receipt = detonate_module.detonate(
                    artifact,
                    "python-script",
                    POLICY,
                    submitted_by="privileged-regression-test",
                )

        self.assertEqual(receipt["outward_report"]["risk_level"], "benign")
        self.assertEqual(receipt["gate"]["final_decision"], "ALLOW")
        self.assertEqual(
            receipt["isolation"],
            {
                "mode": "full-root",
                "namespace_used": True,
                "seccomp_loaded": True,
                "cgroups_used": True,
                "mlock_used": True,
            },
        )
        self.assertNotEqual(observed["wrapper_pid"], observed["child_pid"])
        self.assertEqual(observed["traced_pid"], observed["child_pid"])
        self.assertTrue(observed["members_known"])
        self.assertIn(observed["wrapper_pid"], observed["members"])
        self.assertIn(observed["child_pid"], observed["members"])
        self.assertTrue(receipt["purge"]["verified_externally"])
        self.assertFalse(Path(observed["group"]).exists())

    def test_consistent_isolation_failure_is_unoverridable_and_valid(self) -> None:
        receipt = _valid_legacy_receipt()
        _set_failed_isolation(receipt, "cgroups_used", human_allow=True)
        validate_receipt(receipt)
        self.assertEqual(receipt["gate"]["human_gate_override"], "ALLOW")
        self.assertEqual(receipt["gate"]["final_decision"], "DENY")
        self.assertIs(receipt["gate"]["override_blocked_by_fail_closed"], True)

    def test_validation_derives_optional_cgroup_from_active_policy(self) -> None:
        policy = copy.deepcopy(POLICY)
        policy["isolation"]["full_root_requires_cgroups"] = False
        receipt = _valid_legacy_receipt()
        receipt["snapshot_policy"]["policy_hash"] = _policy_hash(policy)
        receipt["isolation"]["cgroups_used"] = False
        validate_receipt(receipt, active_policy=policy)

    def test_validation_rejects_allow_with_required_isolation_missing(self) -> None:
        for control in (
            "namespace_used",
            "seccomp_loaded",
            "cgroups_used",
            "mlock_used",
        ):
            receipt = _valid_legacy_receipt()
            _set_failed_isolation(receipt, control)
            _force_autonomous_allow(receipt)
            with self.subTest(control=control), self.assertRaises(ValueError):
                validate_receipt(receipt)

    def test_validation_rejects_contradictory_receipt_and_gate_data(self) -> None:
        receipt = _valid_legacy_receipt()
        _set_failed_purge(receipt, include_finding=True)
        receipt["gate"].update(
            {
                "policy_gate_decision": "ALLOW",
                "policy_gate_reason": "no_anomaly_detected",
                "final_decision": "ALLOW",
                "final_authority": "policy_gate_autonomous",
            }
        )
        with self.assertRaises(ValueError):
            validate_receipt(receipt)

    def test_cleanup_returns_all_required_postconditions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            job_dir = Path(temporary) / "mf-run-cleanup"
            job_dir.mkdir()
            (job_dir / "residual").write_text("test", encoding="utf-8")
            purge = _cleanup_legacy_resources(99_999_999, None, job_dir)
        self.assertEqual(
            set(purge),
            {
                "method",
                "verified_externally",
                "process_group_empty",
                "cgroup_empty",
                "cgroup_removed",
                "job_mount_removed",
                "job_directory_removed",
                "processes_remaining",
                "remaining_host_resources",
            },
        )
        self.assertTrue(purge["verified_externally"])
        self.assertEqual(purge["remaining_host_resources"], [])

    def test_cleanup_kills_wrapper_child_and_descendant_process_group(self) -> None:
        process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                (
                    "import os,time\n"
                    "for _ in range(2):\n"
                    " pid=os.fork()\n"
                    " if pid == 0:\n"
                    "  time.sleep(30)\n"
                    "  os._exit(0)\n"
                    "time.sleep(30)\n"
                ),
            ],
            start_new_session=True,
        )
        members: list[int] = []
        try:
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                members, complete = _process_group_members(process.pid)
                if complete and len(members) >= 3:
                    break
                time.sleep(0.01)
            self.assertGreaterEqual(len(members), 3)
            with tempfile.TemporaryDirectory() as temporary:
                job_dir = Path(temporary) / "mf-run-descendants"
                job_dir.mkdir()
                (job_dir / "residual").write_text("test", encoding="utf-8")
                purge = _cleanup_legacy_resources(
                    process.pid,
                    None,
                    job_dir,
                    tracked_pids=set(members),
                )
            self.assertTrue(purge["process_group_empty"])
            self.assertTrue(purge["job_directory_removed"])
            self.assertTrue(purge["verified_externally"])
            self.assertEqual(purge["remaining_host_resources"], [])
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                process.wait(timeout=2)
            except (ChildProcessError, subprocess.TimeoutExpired):
                pass

    def test_required_mlock_failure_reports_not_ready_and_stops_child(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "artifact.py"
            snapshot = root / "snapshot.tar.gz"
            artifact.write_text("pass\n", encoding="utf-8")
            snapshot.write_bytes(b"test")
            job_dir = root / "job"
            job_dir.mkdir()
            control_host, control_child = socket.socketpair(
                socket.AF_UNIX,
                socket.SOCK_SEQPACKET,
            )
            control_host.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            args = argparse.Namespace(
                job_dir=str(job_dir),
                artifact=str(artifact),
                artifact_type="python-script",
                snapshot=str(snapshot),
                budgets=json.dumps(
                    {
                        "wall_clock_sec": 1,
                        "ram_mib": 8,
                        "pids": 4,
                        "max_output_bytes": 1024,
                    }
                ),
                isolation_mode="full-root",
                require_mlock=True,
            )

            def fake_extract(_snapshot: Path, target: Path) -> None:
                (target / "etc").mkdir(parents=True)
                (target / "dev").mkdir(parents=True)

            def fake_mount(
                _source: str | None,
                _target: Path | str,
                fs_type: str | None,
                _flags: int,
                _data: str | None,
            ) -> None:
                if fs_type == "overlay":
                    raise OSError("overlay unavailable in unit test")

            try:
                with (
                    mock.patch.dict(
                        os.environ,
                        {"CINDERMOTE_CONTROL_FD": str(control_child.fileno())},
                    ),
                    mock.patch.object(detonate_module, "_mount", side_effect=fake_mount),
                    mock.patch.object(detonate_module, "_safe_extract", side_effect=fake_extract),
                    mock.patch.object(detonate_module, "_seed_canaries", return_value={}),
                    mock.patch.object(detonate_module, "_prepare_artifact", return_value=["/artifact"]),
                    mock.patch.object(detonate_module, "_seal_file"),
                    mock.patch.object(detonate_module.os, "chroot"),
                    mock.patch.object(detonate_module.os, "chdir"),
                    mock.patch.object(detonate_module.os, "umask"),
                    mock.patch.object(detonate_module.resource, "setrlimit"),
                    mock.patch.object(detonate_module.libc, "mlockall", return_value=-1),
                    mock.patch.object(detonate_module, "_drop_capabilities") as drop_capabilities,
                    mock.patch.object(detonate_module, "install_seccomp") as install_seccomp,
                    mock.patch.object(detonate_module.os, "execve") as execve,
                ):
                    exit_code = _sandbox_child(args)
                status_message = _read_control(control_host)
                self.assertIsNotNone(status_message)
                status = status_message.status
            finally:
                control_host.close()
                control_child.close()

        self.assertEqual(exit_code, 125)
        self.assertIs(status["ready"], False)
        self.assertEqual(status["stage"], "mlock")
        self.assertIs(status["mlock_used"], False)
        drop_capabilities.assert_not_called()
        install_seccomp.assert_not_called()
        execve.assert_not_called()


if __name__ == "__main__":
    unittest.main()
