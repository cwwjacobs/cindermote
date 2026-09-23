#!/usr/bin/env python3
from __future__ import annotations

import copy
import os
import signal
import subprocess
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


PROJECT_DIR = Path(__file__).resolve().parents[2]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

import broker.browser_egress_worker as worker_module  # noqa: E402
from broker.browser_egress_worker import (  # noqa: E402
    BrowserEgressWorker,
    BrowserEgressWorkerError,
    BrowserEgressWorkerProtocolError,
    PROTOCOL_VERSION,
)
from mote.browser_contract import make_probe_request  # noqa: E402


NONCE = "a" * 64
BIND_HOST = "169.254.250.1"
BIND_PORT = 18080
GUEST_IP = "172.30.0.2"
TEST_WORKER_UID = 744
TEST_WORKER_GID = 745


def _clean_telemetry(event_count: int = 1) -> dict:
    return {
        "complete": True,
        "started": True,
        "closed": True,
        "event_overflow": False,
        "inflight_events": 0,
        "active_connections": 0,
        "listener_rejections": 0,
        "connection_attempts": event_count,
        "event_count": event_count,
        "network_bytes": 128,
        "network_byte_limit": 4096,
    }


def _event(sequence: int = 0) -> dict:
    return {
        "sequence": sequence,
        "source": "egress",
        "kind": "network_request",
        "web_origin": None,
        "connect_authority": "example.com:443",
        "disposition": "allowed",
    }


def _start_frame() -> dict:
    return {
        "type": "start",
        "protocol_version": PROTOCOL_VERSION,
        "nonce": NONCE,
        "request": make_probe_request("https://example.com/"),
        "bind_host": BIND_HOST,
        "bind_port": BIND_PORT,
        "allowed_client_ip": GUEST_IP,
    }


class _FakeSecurityOps:
    def __init__(self, *, capabilities_zero: bool = True) -> None:
        self.calls: list[tuple] = []
        self.uid = 0
        self.gid = 0
        self.groups = [0, 10]
        self.no_new_privs = False
        self.dumpable = True
        self.parent_death_signal = 0
        self.parent_pid = 4242
        self.environment_entries = 8
        self.limits: dict[int, tuple[int, int]] = {}
        self._capabilities_zero = capabilities_zero

    def clear_environment(self) -> None:
        self.calls.append(("clear_environment",))
        self.environment_entries = 0

    def set_no_new_privs(self) -> None:
        self.calls.append(("set_no_new_privs",))
        self.no_new_privs = True

    def get_no_new_privs(self) -> bool:
        return self.no_new_privs

    def set_dumpable_false(self) -> None:
        self.calls.append(("set_dumpable_false",))
        self.dumpable = False

    def get_dumpable(self) -> bool:
        return self.dumpable

    def set_parent_death_signal(self, value: int) -> None:
        self.calls.append(("set_parent_death_signal", value))
        self.parent_death_signal = value

    def get_parent_death_signal(self) -> int:
        return self.parent_death_signal

    def get_parent_pid(self) -> int:
        return self.parent_pid

    def set_limit(self, resource_name: int, value: int) -> None:
        self.calls.append(("set_limit", resource_name, value))
        self.limits[resource_name] = (value, value)

    def get_limit(self, resource_name: int) -> tuple[int, int]:
        return self.limits[resource_name]

    def set_groups(self, groups: list[int]) -> None:
        self.calls.append(("set_groups", tuple(groups)))
        self.groups = list(groups)

    def set_gid(self, gid: int) -> None:
        self.calls.append(("set_gid", gid))
        self.gid = gid

    def set_uid(self, uid: int) -> None:
        self.calls.append(("set_uid", uid))
        self.uid = uid

    def get_groups(self) -> list[int]:
        return list(self.groups)

    def get_gid(self) -> int:
        return self.gid

    def get_uid(self) -> int:
        return self.uid

    def get_gids(self) -> tuple[int, int, int]:
        return self.gid, self.gid, self.gid

    def get_uids(self) -> tuple[int, int, int]:
        return self.uid, self.uid, self.uid

    def capabilities_zero(self) -> bool:
        return self._capabilities_zero

    def environment_count(self) -> int:
        return self.environment_entries

    def umask(self, value: int) -> None:
        self.calls.append(("umask", value))

    def chdir_root(self) -> None:
        self.calls.append(("chdir_root",))


class _FakeProxy:
    def __init__(
        self,
        request: dict,
        *,
        bind_host: str,
        bind_port: int,
        allowed_client_ip: str,
    ) -> None:
        if request != make_probe_request("https://example.com/"):
            raise AssertionError("request changed across worker IPC")
        if (bind_host, bind_port, allowed_client_ip) != (
            BIND_HOST,
            BIND_PORT,
            GUEST_IP,
        ):
            raise AssertionError("proxy endpoints changed across worker IPC")
        self.endpoint = (bind_host, bind_port)
        self.stopped = False

    def start(self) -> tuple[str, int]:
        return self.endpoint

    def stop(self) -> None:
        self.stopped = True

    def browser_events_snapshot(self) -> list[dict]:
        if not self.stopped:
            raise AssertionError("telemetry read before revocation")
        return [_event()]

    def telemetry_snapshot(self) -> dict:
        if not self.stopped:
            raise AssertionError("telemetry read before revocation")
        return _clean_telemetry()


class _HangingProxy(_FakeProxy):
    def stop(self) -> None:
        while True:
            time.sleep(0.05)


class _DescendantProxy(_FakeProxy):
    def stop(self) -> None:
        pid = os.fork()
        if pid == 0:
            while True:
                time.sleep(0.05)
        self.stopped = True


class _ForkProcess:
    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.returncode: int | None = None

    def poll(self) -> int | None:
        if self.returncode is not None:
            return self.returncode
        pid, status = os.waitpid(self.pid, os.WNOHANG)
        if pid == 0:
            return None
        self.returncode = os.waitstatus_to_exitcode(status)
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        deadline = None if timeout is None else time.monotonic() + timeout
        while self.poll() is None:
            if deadline is not None and time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired("fork-worker", timeout)
            time.sleep(0.005)
        assert self.returncode is not None
        return self.returncode

    def terminate(self) -> None:
        try:
            os.kill(self.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass

    def kill(self) -> None:
        try:
            os.kill(self.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


class _ForkWorker(BrowserEgressWorker):
    proxy_factory = _FakeProxy

    def _verify_identity(self) -> tuple[int, int]:
        return self._worker_uid, self._worker_gid

    def _spawn(self, control_read: int, status_write: int) -> _ForkProcess:
        pid = os.fork()
        if pid == 0:
            try:
                os.setsid()
                for fd in range(3, 256):
                    if fd not in {control_read, status_write}:
                        try:
                            os.close(fd)
                        except OSError:
                            pass
                code = worker_module._child_proxy_loop(
                    control_read,
                    status_write,
                    worker_module._expected_security_receipt(
                        self._worker_uid, self._worker_gid
                    ),
                    proxy_factory=self.proxy_factory,
                )
            except BaseException:
                code = 70
            os._exit(code)
        process = _ForkProcess(pid)
        process._cindermote_process_group = True
        return process


class WorkerSandboxTests(unittest.TestCase):
    def test_parent_binds_worker_ids_to_the_unique_locked_named_account(self) -> None:
        accounts = {
            "cindermote-proxy": SimpleNamespace(
                pw_name="cindermote-proxy",
                pw_uid=TEST_WORKER_UID,
                pw_gid=TEST_WORKER_GID,
                pw_dir="/nonexistent",
                pw_shell="/usr/sbin/nologin",
            ),
            "cindermote-vmm": SimpleNamespace(
                pw_name="cindermote-vmm",
                pw_uid=742,
                pw_gid=743,
                pw_dir="/nonexistent",
                pw_shell="/usr/sbin/nologin",
            ),
            "nobody": SimpleNamespace(pw_name="nobody", pw_uid=65534),
        }
        groups = {
            "cindermote-proxy": SimpleNamespace(
                gr_name="cindermote-proxy", gr_gid=TEST_WORKER_GID, gr_mem=[]
            ),
            "cindermote-vmm": SimpleNamespace(
                gr_name="cindermote-vmm", gr_gid=743, gr_mem=[]
            ),
            "nobody": SimpleNamespace(gr_name="nobody", gr_gid=65534),
            "nogroup": SimpleNamespace(gr_name="nogroup", gr_gid=65534),
        }
        with (
            mock.patch.object(
                worker_module.pwd,
                "getpwnam",
                side_effect=lambda name: accounts[name],
            ),
            mock.patch.object(
                worker_module.grp,
                "getgrnam",
                side_effect=lambda name: groups[name],
            ),
            mock.patch.object(
                worker_module.pwd, "getpwall", return_value=list(accounts.values())
            ),
            mock.patch.object(
                worker_module.grp, "getgrall", return_value=list(groups.values())
            ),
            mock.patch.object(
                worker_module.os,
                "getgrouplist",
                return_value=[TEST_WORKER_GID],
            ),
            mock.patch.object(
                worker_module, "_account_lock_check", return_value=(True, "locked")
            ),
        ):
            self.assertEqual(
                worker_module._verify_worker_identity(
                    TEST_WORKER_UID, TEST_WORKER_GID
                ),
                (TEST_WORKER_UID, TEST_WORKER_GID),
            )
            with self.assertRaises(BrowserEgressWorkerError):
                worker_module._verify_worker_identity(999, TEST_WORKER_GID)

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX fork")
    def test_bounded_source_bytes_execute_after_filesystem_access_is_dropped(self) -> None:
        sources = worker_module._read_trusted_proxy_sources()
        self.assertEqual(set(sources), set(worker_module._TRUSTED_SOURCE_PATHS))
        pid = os.fork()
        if pid == 0:
            try:
                os.chdir("/")
                for name in (
                    "mote.browser_contract",
                    "mote",
                    "broker.browser_egress_proxy",
                    "broker",
                ):
                    sys.modules.pop(name, None)
                proxy_class = worker_module._execute_proxy_sources_after_drop(sources)
                code = 0 if proxy_class.__name__ == "BrowserEgressProxy" else 71
            except BaseException:
                code = 70
            os._exit(code)
        _pid, status = os.waitpid(pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)

    def test_privilege_drop_order_and_receipt_are_strict(self) -> None:
        ops = _FakeSecurityOps()
        receipt = worker_module._apply_worker_sandbox(
            uid=TEST_WORKER_UID, gid=TEST_WORKER_GID, ops=ops
        )
        self.assertEqual(
            receipt,
            worker_module._expected_security_receipt(
                TEST_WORKER_UID, TEST_WORKER_GID
            ),
        )

        names = [call[0] for call in ops.calls]
        self.assertEqual(names[0], "clear_environment")
        self.assertLess(names.index("set_no_new_privs"), names.index("set_groups"))
        self.assertLess(names.index("set_groups"), names.index("set_gid"))
        self.assertLess(names.index("set_gid"), names.index("set_uid"))
        self.assertLess(names.index("set_uid"), names.index("set_dumpable_false"))
        self.assertLess(
            names.index("set_dumpable_false"),
            names.index("set_parent_death_signal"),
        )
        self.assertEqual(names[-2:], ["umask", "chdir_root"])
        self.assertEqual(
            sum(name == "set_limit" for name in names),
            len(worker_module.RLIMITS),
        )

    def test_incomplete_capability_drop_or_root_target_is_rejected(self) -> None:
        with self.assertRaises(BrowserEgressWorkerProtocolError):
            worker_module._apply_worker_sandbox(
                uid=TEST_WORKER_UID,
                gid=TEST_WORKER_GID,
                ops=_FakeSecurityOps(capabilities_zero=False),
            )
        with self.assertRaises(BrowserEgressWorkerError):
            worker_module._apply_worker_sandbox(
                uid=0, gid=TEST_WORKER_GID, ops=_FakeSecurityOps()
            )

    def test_proxy_import_occurs_only_after_sandbox_receipt(self) -> None:
        order: list[str] = []

        def read_sources() -> dict:
            order.append("source_read")
            return {}

        def execute_sources(sources: dict) -> type[_FakeProxy]:
            self.assertEqual(sources, {})
            order.append("proxy_execute")
            return _FakeProxy

        def sandbox(*, uid: int, gid: int, expected_parent_pid: int) -> dict:
            order.append("sandbox")
            self.assertEqual((uid, gid), (TEST_WORKER_UID, TEST_WORKER_GID))
            self.assertEqual(expected_parent_pid, os.getpid())
            return worker_module._expected_security_receipt(uid, gid)

        with (
            mock.patch.object(
                worker_module,
                "_verify_worker_identity",
                return_value=(TEST_WORKER_UID, TEST_WORKER_GID),
            ),
            mock.patch.object(worker_module, "_apply_worker_sandbox", side_effect=sandbox),
            mock.patch.object(
                worker_module,
                "_read_trusted_proxy_sources",
                side_effect=read_sources,
            ),
            mock.patch.object(
                worker_module,
                "_execute_proxy_sources_after_drop",
                side_effect=execute_sources,
            ),
            mock.patch.object(worker_module, "_child_proxy_loop", return_value=0),
        ):
            self.assertEqual(
                worker_module._child_entry(
                    10,
                    11,
                    os.getpid(),
                    TEST_WORKER_UID,
                    TEST_WORKER_GID,
                ),
                0,
            )
        self.assertEqual(order, ["source_read", "sandbox", "proxy_execute"])


class WorkerProtocolTests(unittest.TestCase):
    def test_ready_and_final_frames_are_session_bound_and_exact(self) -> None:
        ready = {
            "type": "ready",
            "protocol_version": PROTOCOL_VERSION,
            "nonce": NONCE,
            "endpoint": [BIND_HOST, BIND_PORT],
            "security": worker_module._expected_security_receipt(
                TEST_WORKER_UID, TEST_WORKER_GID
            ),
        }
        self.assertEqual(
            worker_module._validate_ready(
                ready,
                nonce=NONCE,
                endpoint=(BIND_HOST, BIND_PORT),
                worker_uid=TEST_WORKER_UID,
                worker_gid=TEST_WORKER_GID,
            ),
            ready,
        )
        final = {
            "type": "final",
            "protocol_version": PROTOCOL_VERSION,
            "nonce": NONCE,
            "events": [_event()],
            "telemetry": _clean_telemetry(),
        }
        events, telemetry = worker_module._validate_final(final, nonce=NONCE)
        self.assertEqual(events, [_event()])
        self.assertTrue(telemetry["complete"])

        rejected = copy.deepcopy(final)
        rejected["telemetry"]["listener_rejections"] = 1
        rejected["telemetry"]["complete"] = False
        _events, rejected_telemetry = worker_module._validate_final(
            rejected, nonce=NONCE
        )
        self.assertFalse(rejected_telemetry["complete"])
        rejected["telemetry"]["complete"] = True
        with self.assertRaises(BrowserEgressWorkerProtocolError):
            worker_module._validate_final(rejected, nonce=NONCE)

        for mutation in ("nonce", "extra", "uid", "authority", "count"):
            with self.subTest(mutation=mutation), self.assertRaises(
                BrowserEgressWorkerProtocolError
            ):
                if mutation == "nonce":
                    candidate = copy.deepcopy(final)
                    candidate["nonce"] = "b" * 64
                elif mutation == "extra":
                    candidate = copy.deepcopy(final)
                    candidate["attacker"] = True
                elif mutation == "uid":
                    bad_ready = copy.deepcopy(ready)
                    bad_ready["security"]["uid"] = 0
                    worker_module._validate_ready(
                        bad_ready,
                        nonce=NONCE,
                        endpoint=(BIND_HOST, BIND_PORT),
                        worker_uid=TEST_WORKER_UID,
                        worker_gid=TEST_WORKER_GID,
                    )
                    continue
                elif mutation == "authority":
                    candidate = copy.deepcopy(final)
                    candidate["events"][0]["connect_authority"] = "127.0.0.1:443"
                else:
                    candidate = copy.deepcopy(final)
                    candidate["telemetry"]["event_count"] = 2
                worker_module._validate_final(candidate, nonce=NONCE)

        for unsafe_authority in (
            "singlelabel:443",
            "example.com.:443",
            "service.internal:443",
            "example.com:0",
        ):
            candidate = copy.deepcopy(final)
            candidate["events"][0]["connect_authority"] = unsafe_authority
            with self.subTest(authority=unsafe_authority), self.assertRaises(
                BrowserEgressWorkerProtocolError
            ):
                worker_module._validate_final(candidate, nonce=NONCE)

    def test_framing_rejects_duplicates_and_excessive_lengths(self) -> None:
        read_fd, write_fd = os.pipe()
        try:
            deadline = time.monotonic() + 1.0
            worker_module._write_frame(
                write_fd,
                {"type": "stop", "nonce": NONCE},
                4096,
                deadline,
            )
            self.assertEqual(
                worker_module._read_frame(read_fd, 4096, deadline),
                {"type": "stop", "nonce": NONCE},
            )
        finally:
            os.close(read_fd)
            os.close(write_fd)

        duplicate = b'{"type":"x","type":"y"}'
        with self.assertRaises(BrowserEgressWorkerProtocolError):
            worker_module._json_object(duplicate)

        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, worker_module._FRAME_HEADER.pack(4097))
            with self.assertRaises(BrowserEgressWorkerProtocolError):
                worker_module._read_frame(
                    read_fd,
                    4096,
                    time.monotonic() + 1.0,
                )
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_config_accepts_runtime_link_local_bind_but_not_link_local_guest(self) -> None:
        self.assertEqual(worker_module._validate_child_config(_start_frame())["bind_host"], BIND_HOST)
        invalid = _start_frame()
        invalid["allowed_client_ip"] = BIND_HOST
        with self.assertRaises(BrowserEgressWorkerError):
            worker_module._validate_child_config(invalid)


@unittest.skipUnless(hasattr(os, "fork"), "requires POSIX fork")
class WorkerProcessTests(unittest.TestCase):
    @unittest.skipIf(os.geteuid() == 0, "non-root refusal test")
    def test_production_child_refuses_to_substitute_the_callers_identity(self) -> None:
        worker = BrowserEgressWorker(
            make_probe_request("https://example.com/"),
            bind_host=BIND_HOST,
            bind_port=BIND_PORT,
            allowed_client_ip=GUEST_IP,
            worker_uid=TEST_WORKER_UID,
            worker_gid=TEST_WORKER_GID,
            ready_timeout_sec=1.0,
        )
        with self.assertRaises(BrowserEgressWorkerError):
            with mock.patch.object(
                worker_module,
                "_verify_worker_identity",
                return_value=(TEST_WORKER_UID, TEST_WORKER_GID),
            ):
                worker.start()
        self.assertFalse(worker.purge_verified)
        worker.stop()
        self.assertEqual(worker.browser_events_snapshot(), worker_module._failure_events())
        self.assertFalse(worker.telemetry_snapshot()["complete"])
        self.assertTrue(worker.purge_verified)

    def test_parent_lifecycle_uses_a_separate_current_uid_test_process(self) -> None:
        worker = _ForkWorker(
            make_probe_request("https://example.com/"),
            bind_host=BIND_HOST,
            bind_port=BIND_PORT,
            allowed_client_ip=GUEST_IP,
            worker_uid=TEST_WORKER_UID,
            worker_gid=TEST_WORKER_GID,
            ready_timeout_sec=1.0,
            stop_timeout_sec=1.0,
        )
        self.assertFalse(worker.purge_verified)
        with self.assertRaises(AttributeError):
            worker.purge_verified = True  # type: ignore[misc]
        self.assertEqual(worker.start(), (BIND_HOST, BIND_PORT))
        self.assertFalse(worker.purge_verified)
        receipt = worker.readiness_receipt
        assert receipt is not None
        self.assertEqual(receipt["security"]["uid"], TEST_WORKER_UID)
        process = worker._process
        assert process is not None
        self.assertNotEqual(process.pid, os.getpid())

        worker.stop()
        self.assertEqual(worker.browser_events_snapshot(), [_event()])
        self.assertTrue(worker.telemetry_snapshot()["complete"])
        self.assertEqual(process.poll(), 0)
        self.assertTrue(worker.purge_verified)

    def test_hung_stop_is_killed_and_returns_fixed_failure_telemetry(self) -> None:
        class HangingForkWorker(_ForkWorker):
            proxy_factory = _HangingProxy

        worker = HangingForkWorker(
            make_probe_request("https://example.com/"),
            bind_host=BIND_HOST,
            bind_port=BIND_PORT,
            allowed_client_ip=GUEST_IP,
            worker_uid=TEST_WORKER_UID,
            worker_gid=TEST_WORKER_GID,
            ready_timeout_sec=1.0,
            stop_timeout_sec=0.2,
        )
        worker.start()
        process = worker._process
        assert process is not None
        started = time.monotonic()
        worker.stop()
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertEqual(worker.browser_events_snapshot(), worker_module._failure_events())
        self.assertFalse(worker.telemetry_snapshot()["complete"])
        self.assertIsNotNone(process.poll())
        self.assertTrue(worker.purge_verified)

    def test_surviving_group_descendant_is_killed_and_invalidates_telemetry(self) -> None:
        class DescendantForkWorker(_ForkWorker):
            proxy_factory = _DescendantProxy

        worker = DescendantForkWorker(
            make_probe_request("https://example.com/"),
            bind_host=BIND_HOST,
            bind_port=BIND_PORT,
            allowed_client_ip=GUEST_IP,
            worker_uid=TEST_WORKER_UID,
            worker_gid=TEST_WORKER_GID,
            ready_timeout_sec=1.0,
            stop_timeout_sec=1.0,
        )
        worker.start()
        worker.stop()
        self.assertFalse(worker.telemetry_snapshot()["complete"])
        self.assertEqual(worker.browser_events_snapshot(), worker_module._failure_events())
        self.assertTrue(worker.purge_verified)

    def test_purge_never_infers_from_clean_telemetry(self) -> None:
        class UnverifiableForkWorker(_ForkWorker):
            def _wait_process_group_empty(
                self,
                process: object,
                timeout: float = worker_module.PURGE_RECHECK_SEC,
            ) -> bool:
                return False

        worker = UnverifiableForkWorker(
            make_probe_request("https://example.com/"),
            bind_host=BIND_HOST,
            bind_port=BIND_PORT,
            allowed_client_ip=GUEST_IP,
            worker_uid=TEST_WORKER_UID,
            worker_gid=TEST_WORKER_GID,
            ready_timeout_sec=1.0,
            stop_timeout_sec=1.0,
        )
        worker.start()
        worker.stop()
        self.assertTrue(worker.telemetry_snapshot()["complete"])
        self.assertFalse(worker.purge_verified)

    def test_production_spawn_is_isolated_and_inherits_only_control_fds(self) -> None:
        worker = BrowserEgressWorker(
            make_probe_request("https://example.com/"),
            bind_host=BIND_HOST,
            bind_port=BIND_PORT,
            allowed_client_ip=GUEST_IP,
            worker_uid=TEST_WORKER_UID,
            worker_gid=TEST_WORKER_GID,
        )
        fake_process = mock.Mock()
        with mock.patch.object(
            worker_module.subprocess,
            "Popen",
            return_value=fake_process,
        ) as popen:
            self.assertIs(worker._spawn(10, 11), fake_process)
        _args, kwargs = popen.call_args
        command = _args[0]
        self.assertIn("-I", command)
        self.assertIn("-S", command)
        self.assertIn("-B", command)
        self.assertEqual(command[-2:], [str(TEST_WORKER_UID), str(TEST_WORKER_GID)])
        self.assertEqual(kwargs["env"], {})
        self.assertEqual(kwargs["cwd"], "/")
        self.assertEqual(kwargs["pass_fds"], (10, 11))
        self.assertTrue(kwargs["close_fds"])
        self.assertTrue(kwargs["start_new_session"])


if __name__ == "__main__":
    unittest.main()
