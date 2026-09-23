from __future__ import annotations

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
from types import SimpleNamespace
from unittest import mock

from cindermote.gate.policy_gate import apply_scoring_matrix
from cindermote.mote import firecracker_runtime as runtime
from cindermote.mote.browser_contract import make_probe_request


class FirecrackerRuntimePrimitiveTests(unittest.TestCase):
    def test_dedicated_vmm_identity_is_resolved_by_name(self) -> None:
        account = SimpleNamespace(
            pw_uid=742,
            pw_gid=743,
            pw_dir="/nonexistent",
            pw_shell="/usr/sbin/nologin",
        )
        group = SimpleNamespace(gr_gid=743, gr_mem=[])
        with (
            mock.patch.object(runtime.pwd, "getpwnam", return_value=account) as passwd,
            mock.patch.object(runtime.grp, "getgrnam", return_value=group) as groups,
            mock.patch.object(runtime.os, "getgrouplist", return_value=[743]),
            mock.patch.object(runtime.pwd, "getpwall", return_value=[]),
            mock.patch.object(runtime.grp, "getgrall", return_value=[]),
            mock.patch.object(
                runtime, "_account_lock_check", return_value=(True, "password=locked")
            ),
        ):
            ok, detail, uid, gid = runtime._vmm_identity_check()

        self.assertTrue(ok, detail)
        self.assertEqual((uid, gid), (742, 743))
        passwd.assert_called_once_with("cindermote-vmm")
        groups.assert_called_once_with("cindermote-vmm")

    def test_generic_or_supplementary_vmm_identity_is_rejected(self) -> None:
        account = SimpleNamespace(
            pw_uid=65534,
            pw_gid=65534,
            pw_dir="/nonexistent",
            pw_shell="/usr/bin/nologin",
        )
        group = SimpleNamespace(gr_gid=65534, gr_mem=["another-service"])
        with (
            mock.patch.object(runtime.pwd, "getpwnam", return_value=account),
            mock.patch.object(runtime.grp, "getgrnam", return_value=group),
            mock.patch.object(runtime.os, "getgrouplist", return_value=[65534, 44]),
            mock.patch.object(runtime.pwd, "getpwall", return_value=[]),
            mock.patch.object(runtime.grp, "getgrall", return_value=[]),
            mock.patch.object(
                runtime, "_account_lock_check", return_value=(False, "password unlocked")
            ),
        ):
            ok, detail, uid, gid = runtime._vmm_identity_check()

        self.assertFalse(ok)
        self.assertEqual((uid, gid), (65534, 65534))
        self.assertIn("unsafe uid=65534", detail)
        self.assertIn("supplementary groups", detail)
        self.assertIn("other members", detail)
        self.assertIn("password unlocked", detail)

    def test_proxy_identity_is_locked_unique_and_disjoint_from_vmm(self) -> None:
        proxy_account = SimpleNamespace(
            pw_name="cindermote-proxy",
            pw_uid=744,
            pw_gid=745,
            pw_dir="/nonexistent",
            pw_shell="/usr/sbin/nologin",
        )
        vmm_account = SimpleNamespace(pw_name="cindermote-vmm", pw_uid=742)
        nobody = SimpleNamespace(pw_name="nobody", pw_uid=65534)
        proxy_group = SimpleNamespace(
            gr_name="cindermote-proxy", gr_gid=745, gr_mem=[]
        )
        vmm_group = SimpleNamespace(gr_name="cindermote-vmm", gr_gid=743, gr_mem=[])
        nobody_group = SimpleNamespace(gr_name="nobody", gr_gid=65534, gr_mem=[])

        def account(name: str) -> object:
            return {
                "cindermote-proxy": proxy_account,
                "cindermote-vmm": vmm_account,
                "nobody": nobody,
            }[name]

        def group(name: str) -> object:
            return {
                "cindermote-proxy": proxy_group,
                "cindermote-vmm": vmm_group,
                "nobody": nobody_group,
                "nogroup": nobody_group,
            }[name]

        with (
            mock.patch.object(runtime.pwd, "getpwnam", side_effect=account),
            mock.patch.object(runtime.grp, "getgrnam", side_effect=group),
            mock.patch.object(runtime.os, "getgrouplist", return_value=[745]),
            mock.patch.object(
                runtime.pwd,
                "getpwall",
                return_value=[proxy_account, vmm_account, nobody],
            ),
            mock.patch.object(
                runtime.grp,
                "getgrall",
                return_value=[proxy_group, vmm_group, nobody_group],
            ),
            mock.patch.object(
                runtime, "_account_lock_check", return_value=(True, "password=locked")
            ),
        ):
            ok, detail, uid, gid = runtime._proxy_identity_check(742, 743)
            self.assertTrue(ok, detail)
            self.assertEqual((uid, gid), (744, 745))

            overlapping, overlap_detail, _, _ = runtime._proxy_identity_check(744, 743)
            self.assertFalse(overlapping)
            self.assertIn("overlaps", overlap_detail)

    def test_tap_is_owned_by_the_resolved_vmm_identity(self) -> None:
        paths = runtime._network_paths(
            "mf-web-1234abcd",
            Path("/run/cindermote"),
            Path("/sys/fs/cgroup/cindermote"),
        )
        with mock.patch.object(runtime, "_run") as run:
            runtime._setup_network(paths, 742, 743)

        commands = [call.args[0] for call in run.call_args_list]
        self.assertIn(
            [
                "ip", "-n", paths.netns_name, "tuntap", "add", "dev", "tap0",
                "mode", "tap", "user", "742", "group", "743",
            ],
            commands,
        )

    def test_egress_worker_must_be_reaped_for_overall_purge(self) -> None:
        purge = runtime._purge_summary(
            processes_reaped=True,
            cgroup_removed=True,
            network_namespace_removed=True,
            ram_jail_removed=True,
            egress_worker_reaped=False,
        )

        self.assertFalse(purge["verified_externally"])
        self.assertFalse(purge["egress_worker_reaped"])

    def test_clean_proxy_telemetry_cannot_replace_worker_reap_proof(self) -> None:
        self.assertFalse(
            runtime._egress_stream_complete(
                proxy_present=True,
                egress_worker_reaped=False,
                network_namespace_removed=True,
                telemetry={"complete": True},
            )
        )
        self.assertTrue(
            runtime._egress_stream_complete(
                proxy_present=True,
                egress_worker_reaped=True,
                network_namespace_removed=True,
                telemetry={"complete": True},
            )
        )

    def test_missing_worker_reap_proof_forces_a_fail_closed_reduction(self) -> None:
        reduction = {
            "decision": "ALLOW",
            "complete": True,
            "telemetry_incomplete": False,
            "fail_closed": False,
        }

        runtime._enforce_purge_gate(reduction, False)

        self.assertEqual(reduction["decision"], "DENY")
        self.assertFalse(reduction["complete"])
        self.assertTrue(reduction["telemetry_incomplete"])
        self.assertTrue(reduction["fail_closed"])

    def test_stale_discovery_accepts_only_exact_owned_names(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime_root = root / "run"
            cgroup_root = root / "cgroup"
            jailers = runtime_root / "jailer" / "firecracker"
            cgroups = cgroup_root / "firecracker"
            jailers.mkdir(parents=True)
            cgroups.mkdir(parents=True)
            (jailers / "mf-web-aabbccdd").mkdir()
            (jailers / "mf-web-AABBCCDD").mkdir()
            (jailers / "mf-web-aabbccd").mkdir()
            (cgroups / "mf-web-11223344").mkdir()
            listings = [
                subprocess.CompletedProcess(
                    ["ip", "netns", "list"],
                    0,
                    stdout="mf-deadbeef (id: 1)\nother-deadbeef\nmf-DEADBEEF\n",
                    stderr="",
                ),
                subprocess.CompletedProcess(
                    ["ip", "-o", "link", "show"],
                    0,
                    stdout=(
                        "10: mfhcafebabe@if9: <BROADCAST> mtu 1500\n"
                        "11: mfhCAFECAFE@if8: <BROADCAST> mtu 1500\n"
                        "12: othermfh01234567: <BROADCAST> mtu 1500\n"
                    ),
                    stderr="",
                ),
            ]
            with mock.patch.object(runtime, "_run", side_effect=listings):
                tokens = runtime._owned_stale_job_tokens(runtime_root, cgroup_root)

        self.assertEqual(tokens, {"aabbccdd", "11223344", "deadbeef", "cafebabe"})

    def test_stale_reconciliation_removes_only_the_exact_job(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime_root = root / "run"
            cgroup_root = root / "cgroup"
            exact_jail = runtime_root / "jailer" / "firecracker" / "mf-web-deadbeef"
            unrelated_jail = runtime_root / "jailer" / "firecracker" / "mf-web-DEADBEEF"
            exact_cgroup = cgroup_root / "firecracker" / "mf-web-deadbeef"
            exact_jail.mkdir(parents=True)
            unrelated_jail.mkdir()
            exact_cgroup.mkdir(parents=True)
            with (
                mock.patch.object(runtime, "_owned_stale_job_tokens", return_value={"deadbeef"}),
                mock.patch.object(runtime, "_cleanup_network", return_value=True),
            ):
                runtime._reconcile_stale_browser_jobs(runtime_root, cgroup_root)

            self.assertFalse(exact_jail.exists())
            self.assertFalse(exact_cgroup.exists())
            self.assertTrue(unrelated_jail.exists())

    def test_stale_reconciliation_fails_closed_on_residual_network(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (
                mock.patch.object(runtime, "_owned_stale_job_tokens", return_value={"deadbeef"}),
                mock.patch.object(runtime, "_cleanup_network", return_value=False),
            ):
                with self.assertRaises(runtime.FirecrackerRuntimeError):
                    runtime._reconcile_stale_browser_jobs(root / "run", root / "cgroup")

    def test_jailer_supervisor_command_is_parent_bound_and_argument_safe(self) -> None:
        with mock.patch.object(runtime.shutil, "which", return_value="/usr/bin/python3"):
            command = runtime._supervised_jailer_command(
                ["/trusted/jailer", "--id", "mf-web-deadbeef"],
                orchestrator_pid=4242,
            )

        self.assertEqual(command[:5], ["/usr/bin/python3", "-I", "-S", "-B", "-c"])
        self.assertIn("PR_SET_PDEATHSIG", command[5])
        self.assertIn("os.killpg(child_pid, signal.SIGKILL)", command[5])
        self.assertEqual(command[6:], ["4242", "/trusted/jailer", "--id", "mf-web-deadbeef"])

    @unittest.skipUnless(hasattr(os, "fork") and sys.platform.startswith("linux"), "requires Linux fork/prctl")
    def test_jailer_supervisor_kills_child_when_orchestrator_dies(self) -> None:
        def alive(pid: int) -> bool:
            try:
                fields = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").split()
            except (FileNotFoundError, ProcessLookupError):
                return False
            return len(fields) > 2 and fields[2] != "Z"

        def kill_if_alive(pid: int) -> None:
            if not alive(pid):
                return
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            supervisor_file = root / "supervisor.pid"
            child_file = root / "child.pid"
            shim_pid = os.fork()
            if shim_pid == 0:
                child_code = (
                    "import os,sys,time;"
                    "open(sys.argv[1],'w',encoding='ascii').write(str(os.getpid()));"
                    "time.sleep(30)"
                )
                target = [sys.executable, "-I", "-S", "-B", "-c", child_code, str(child_file)]
                command = runtime._supervised_jailer_command(
                    target,
                    orchestrator_pid=os.getpid(),
                )
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                supervisor_file.write_text(str(process.pid), encoding="ascii")
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    try:
                        if child_file.read_text(encoding="ascii").strip().isdigit():
                            break
                    except FileNotFoundError:
                        pass
                    time.sleep(0.01)
                os._exit(0)

            os.waitpid(shim_pid, 0)
            self.assertTrue(supervisor_file.exists())
            self.assertTrue(child_file.exists())
            supervisor_pid = int(supervisor_file.read_text(encoding="ascii"))
            child_pid = int(child_file.read_text(encoding="ascii"))
            self.addCleanup(kill_if_alive, child_pid)
            self.addCleanup(kill_if_alive, supervisor_pid)
            deadline = time.monotonic() + 3
            while (alive(supervisor_pid) or alive(child_pid)) and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertFalse(alive(child_pid))
            self.assertFalse(alive(supervisor_pid))

    @unittest.skipUnless(hasattr(os, "fork") and sys.platform.startswith("linux"), "requires Linux fork/prctl")
    def test_jailer_supervisor_closes_immediate_parent_death_race(self) -> None:
        def alive(pid: int) -> bool:
            try:
                fields = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").split()
            except (FileNotFoundError, ProcessLookupError):
                return False
            return len(fields) > 2 and fields[2] != "Z"

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            supervisor_file = root / "supervisor.pid"
            child_file = root / "child.pid"
            shim_pid = os.fork()
            if shim_pid == 0:
                child_code = (
                    "import os,sys,time;"
                    "open(sys.argv[1],'w',encoding='ascii').write(str(os.getpid()));"
                    "time.sleep(30)"
                )
                target = [sys.executable, "-I", "-S", "-B", "-c", child_code, str(child_file)]
                process = subprocess.Popen(
                    runtime._supervised_jailer_command(
                        target,
                        orchestrator_pid=os.getpid(),
                    ),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                supervisor_file.write_text(str(process.pid), encoding="ascii")
                os._exit(0)

            os.waitpid(shim_pid, 0)
            self.assertTrue(supervisor_file.exists())
            supervisor_pid = int(supervisor_file.read_text(encoding="ascii"))
            deadline = time.monotonic() + 3
            while alive(supervisor_pid) and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertFalse(alive(supervisor_pid))
            if child_file.exists():
                child_pid = int(child_file.read_text(encoding="ascii"))
                deadline = time.monotonic() + 1
                while alive(child_pid) and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertFalse(alive(child_pid))

    def test_vsock_line_reader_preserves_coalesced_messages(self) -> None:
        reader, writer = socket.socketpair()
        self.addCleanup(reader.close)
        self.addCleanup(writer.close)
        writer.sendall(b"OK 3\n{\"type\":\"hello\"}\n")
        buffered = bytearray()
        deadline = time.monotonic() + 1

        self.assertEqual(
            runtime._read_line(reader, buffered, 64, deadline),
            b"OK 3\n",
        )
        self.assertEqual(
            runtime._read_line(reader, buffered, 4096, deadline),
            b'{"type":"hello"}\n',
        )
        self.assertEqual(buffered, bytearray())

    def test_staged_copy_is_hash_bound_and_not_writable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            destination = root / "destination"
            source.write_bytes(b"bound runtime asset")

            observed = runtime._stage_copy(source, destination, 0o400)

            self.assertEqual(observed, hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertEqual(destination.read_bytes(), source.read_bytes())
            self.assertEqual(destination.stat().st_mode & 0o777, 0o400)

    def test_guest_artifacts_are_strict_metadata_only(self) -> None:
        digest = "a" * 64
        clean = {
            "raw_retained": False,
            "attestation_complete": True,
            "dom_sha256": digest,
            "visible_text_sha256": digest,
            "screenshot_sha256": digest,
            "console_event_count": 3,
        }
        self.assertEqual(runtime._validate_guest_artifacts(clean, 10), clean)

        for mutation in (
            {**clean, "raw_retained": True},
            {**clean, "dom_sha256": "not-a-digest"},
            {**clean, "console_event_count": True},
            {**clean, "console_event_count": 11},
            {**clean, "raw_page_text": "must never cross the VM boundary"},
        ):
            with self.subTest(mutation=mutation):
                with self.assertRaises(runtime.FirecrackerRuntimeError):
                    runtime._validate_guest_artifacts(mutation, 10)

    def test_guest_cdp_v1_origin_translates_to_host_web_origin_evidence(self) -> None:
        legacy = {
            "evidence_version": "cindermote.browser-evidence/v1",
            "events": [
                {
                    "sequence": 0,
                    "source": "cdp",
                    "kind": "network_request",
                    "origin": "https://example.org",
                    "disposition": "allowed",
                }
            ],
            "streams": {
                "browser": {"complete": True, "event_count": 0},
                "cdp": {"complete": True, "event_count": 1},
                "egress": {"complete": False, "event_count": 0},
                "vm": {"complete": False, "event_count": 0},
            },
        }

        translated = runtime._translate_guest_evidence_v1(legacy)

        self.assertEqual(translated["evidence_version"], "cindermote.browser-evidence/v2")
        self.assertEqual(
            translated["events"][0],
            {
                "sequence": 0,
                "source": "cdp",
                "kind": "network_request",
                "web_origin": "https://example.org",
                "connect_authority": None,
                "disposition": "allowed",
            },
        )

    def test_guest_cannot_claim_host_proxy_witnesses(self) -> None:
        legacy = {
            "evidence_version": "cindermote.browser-evidence/v1",
            "events": [
                {
                    "sequence": 0,
                    "source": "egress",
                    "kind": "network_request",
                    "origin": "https://example.org",
                    "disposition": "allowed",
                }
            ],
            "streams": {
                "browser": {"complete": True, "event_count": 0},
                "cdp": {"complete": True, "event_count": 0},
                "egress": {"complete": False, "event_count": 1},
                "vm": {"complete": False, "event_count": 0},
            },
        }
        with self.assertRaises(runtime.FirecrackerRuntimeError):
            runtime._translate_guest_evidence_v1(legacy)

    def test_missing_asset_lock_fails_preflight_without_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = runtime.preflight_firecracker(
                cache_dir=root / "cache",
                runtime_root=root / "run",
                cgroup_root=root / "cgroup",
                asset_lock_path=root / "missing-lock.json",
            )

        self.assertFalse(report.ready)
        self.assertEqual([check.name for check in report.checks], ["asset_lock"])
        self.assertTrue(report.checks[0].required)

    def test_browser_probe_never_falls_back_when_firecracker_is_unready(self) -> None:
        called = False

        def proxy_factory(*_args: object, **_kwargs: object) -> object:
            nonlocal called
            called = True
            raise AssertionError("proxy must not start before Firecracker admission")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(runtime.FirecrackerUnavailable):
                runtime.run_browser_probe(
                    make_probe_request("https://example.org/"),
                    cache_dir=root / "empty-cache",
                    runtime_root=root / "not-tmpfs",
                    cgroup_root=root / "cgroup",
                    proxy_factory=proxy_factory,
                )
        self.assertFalse(called)


class FirecrackerPolicyGateTests(unittest.TestCase):
    def test_runtime_does_not_compare_connect_authorities_to_cdp_origins(self) -> None:
        source = (runtime.PROJECT_DIR / "mote" / "firecracker_runtime.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("egress_origins.issubset(cdp_origins)", source)

    def test_integrity_budget_failure_cannot_be_overridden_to_allow(self) -> None:
        report = {
            "risk_level": "hostile",
            "evidence": [
                {
                    "tap_category": "resource_use",
                    "rule_id": "web_event_budget_exceeded",
                    "count": 1,
                }
            ],
            "capabilities_requested": ["browser.navigate"],
            "destinations": [],
            "canaries_tripped": [],
            "uncertainty": 1.0,
        }
        result = apply_scoring_matrix(report, {"job": "ALLOW"}, "job")

        self.assertEqual(result["final_decision"], "DENY")
        self.assertEqual(result["final_authority"], "fail_closed_infrastructure_gate")
        self.assertTrue(result["override_blocked_by_fail_closed"])


class BrowserRootfsReceiptTests(unittest.TestCase):
    def test_receipt_binds_the_exact_rootfs_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / "rootfs.ext4"
            image.write_bytes(b"rootfs")
            digest = hashlib.sha256(b"rootfs").hexdigest()
            receipt = root / "receipt.json"
            source_paths = {
                "guest/browser_agent.py": runtime.PROJECT_DIR / "guest" / "browser_agent.py",
                "guest/agent_probe_agent.py": runtime.PROJECT_DIR / "guest" / "agent_probe_agent.py",
                "agent_probe/__init__.py": runtime.PROJECT_DIR / "agent_probe" / "__init__.py",
                "agent_probe/canonical.py": runtime.PROJECT_DIR / "agent_probe" / "canonical.py",
                "agent_probe/evidence.py": runtime.PROJECT_DIR / "agent_probe" / "evidence.py",
                "agent_probe/hpke.py": runtime.PROJECT_DIR / "agent_probe" / "hpke.py",
                "agent_probe/protocol.py": runtime.PROJECT_DIR / "agent_probe" / "protocol.py",
                "agent_probe/secretstream.py": runtime.PROJECT_DIR / "agent_probe" / "secretstream.py",
                "mote/browser_contract.py": runtime.PROJECT_DIR / "mote" / "browser_contract.py",
                "guest/cindermote-init": runtime.PROJECT_DIR / "guest" / "cindermote-init",
                "images/firecracker/Containerfile": runtime.PROJECT_DIR
                / "images"
                / "firecracker"
                / "Containerfile",
                "images/firecracker/RootfsToolchain.Containerfile": runtime.PROJECT_DIR
                / "images"
                / "firecracker"
                / "RootfsToolchain.Containerfile",
                "scripts/build-rootfs-in-toolchain.sh": runtime.PROJECT_DIR
                / "scripts"
                / "build-rootfs-in-toolchain.sh",
                "scripts/build-firecracker-image.sh": runtime.PROJECT_DIR
                / "scripts"
                / "build-firecracker-image.sh",
            }
            receipt.write_text(
                json.dumps(
                    {
                        "schema_version": "cindermote.browser-rootfs/v1",
                        "source_date_epoch": 1784160000,
                        "filesystem_uuid": "7a1c357e-64a8-4ef8-9cb1-7a2fd676dd10",
                        "directory_hash_seed": "11111111-2222-3333-4444-555555555555",
                        "rootfs": {
                            "sha256": digest,
                            "size_mib": 1536,
                            "read_only_runtime": True,
                        },
                        "browser": {
                            "version": "Chromium test",
                            "binary_sha256": "b" * 64,
                            "sandbox_required": True,
                            "sandbox_uid": 0,
                            "sandbox_gid": 0,
                            "sandbox_mode": "04755",
                        },
                        "runtime_packages": {
                            "python3-cryptography": "test",
                            "libsodium23": "test",
                        },
                        "build_inputs": runtime.ROOTFS_BUILD_INPUTS,
                        "guest_writes": "tmpfs_only",
                        "sources": {
                            name: hashlib.sha256(path.read_bytes()).hexdigest()
                            for name, path in source_paths.items()
                        },
                    }
                ),
                encoding="utf-8",
            )
            receipt.chmod(0o444)
            lock = {
                "path": "images/browser-rootfs.ext4",
                "sha256": digest,
                "build_receipt_path": "images/browser-rootfs.receipt.json",
                "build_receipt_sha256": hashlib.sha256(receipt.read_bytes()).hexdigest(),
                "required_receipt_schema": "cindermote.browser-rootfs/v1",
                "source_date_epoch": 1784160000,
                "filesystem_uuid": "7a1c357e-64a8-4ef8-9cb1-7a2fd676dd10",
                "directory_hash_seed": "11111111-2222-3333-4444-555555555555",
            }

            ok, _detail, loaded = runtime._rootfs_receipt_check(
                image, receipt, lock
            )
            self.assertTrue(ok)
            self.assertEqual(loaded["rootfs"]["sha256"], digest)

            image.write_bytes(b"changed")
            ok, _detail, loaded = runtime._rootfs_receipt_check(
                image, receipt, lock
            )
            self.assertFalse(ok)
            self.assertIsNone(loaded)

    def test_receipt_itself_must_match_the_asset_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / "rootfs.ext4"
            receipt = root / "receipt.json"
            image.write_bytes(b"rootfs")
            receipt.write_text("{}\n", encoding="utf-8")
            image.chmod(0o444)
            receipt.chmod(0o444)
            lock = {
                "path": "images/browser-rootfs.ext4",
                "sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
                "build_receipt_path": "images/browser-rootfs.receipt.json",
                "build_receipt_sha256": "0" * 64,
                "required_receipt_schema": "cindermote.browser-rootfs/v1",
                "source_date_epoch": 1784160000,
                "filesystem_uuid": "7a1c357e-64a8-4ef8-9cb1-7a2fd676dd10",
                "directory_hash_seed": "11111111-2222-3333-4444-555555555555",
            }

            ok, detail, loaded = runtime._rootfs_receipt_check(image, receipt, lock)

            self.assertFalse(ok)
            self.assertIn("build receipt is not locked", detail)
            self.assertIsNone(loaded)


if __name__ == "__main__":
    unittest.main()
