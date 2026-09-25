#!/usr/bin/env python3
"""Privilege-separated supervisor for :mod:`browser_egress_proxy`.

The root Firecracker orchestrator must instantiate :class:`BrowserEgressWorker`,
not ``BrowserEgressProxy``.  This parent-side module never imports the HTTP
parser.  It execs a fresh Python child with an empty environment and private
pipe control channel.  The child applies irreversible privilege and resource
limits before importing, constructing, or listening with the proxy.

The IPC contract is deliberately tiny: one bounded start frame, one bounded
readiness receipt, one stop frame, and one strictly validated final telemetry
frame.  Missing, malformed, late, or process-unbound telemetry becomes a fixed
fail-closed result in the parent.
"""

from __future__ import annotations

import copy
import ctypes
import grp
import ipaddress
import json
import math
import os
import pwd
import re
import resource
import secrets
import select
import signal
import stat
import struct
import subprocess
import sys
import threading
import time
import types
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import urlsplit


PROTOCOL_VERSION = "cindermote.browser-egress-worker/v2"
WORKER_USER = "cindermote-proxy"
WORKER_GROUP = "cindermote-proxy"
VMM_USER = "cindermote-vmm"
VMM_GROUP = "cindermote-vmm"

READY_TIMEOUT_SEC = 5.0
STOP_TIMEOUT_SEC = 3.0
KILL_GRACE_SEC = 0.5
PURGE_RECHECK_SEC = 0.5
MAX_CONFIG_FRAME_BYTES = 128 * 1024
MAX_STATUS_FRAME_BYTES = 1024 * 1024
MAX_FINAL_EVENTS = 4096
MAX_EVENT_ORIGIN_BYTES = 512
MAX_COUNTER_VALUE = 1_000_000
MAX_NETWORK_BYTES = 64 * 1024 * 1024

RLIMITS = {
    "core": (resource.RLIMIT_CORE, 0),
    "file_size": (resource.RLIMIT_FSIZE, 0),
    "open_files": (resource.RLIMIT_NOFILE, 64),
    "processes": (resource.RLIMIT_NPROC, 32),
    "address_space": (resource.RLIMIT_AS, 256 * 1024 * 1024),
}

READY_KEYS = {"type", "protocol_version", "nonce", "endpoint", "security"}
SECURITY_KEYS = {
    "uid",
    "gid",
    "uids",
    "gids",
    "supplementary_groups",
    "no_new_privs",
    "dumpable",
    "parent_death_signal",
    "parent_pid_bound",
    "capabilities_zero",
    "environment_entries",
    "rlimits",
}
FINAL_KEYS = {"type", "protocol_version", "nonce", "events", "telemetry"}
EVENT_KEYS = {
    "sequence",
    "source",
    "kind",
    "web_origin",
    "connect_authority",
    "disposition",
}
TELEMETRY_KEYS = {
    "complete",
    "started",
    "closed",
    "event_overflow",
    "inflight_events",
    "active_connections",
    "listener_rejections",
    "connection_attempts",
    "event_count",
    "network_bytes",
    "network_byte_limit",
}

_FRAME_HEADER = struct.Struct(">I")
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_THIS_FILE = Path(__file__).resolve()
_TRUSTED_SOURCE_PATHS = {
    "mote.browser_contract": _PROJECT_ROOT / "mote" / "browser_contract.py",
    "broker.browser_egress_proxy": _PROJECT_ROOT / "broker" / "browser_egress_proxy.py",
}
_MAX_TRUSTED_SOURCE_BYTES = 2 * 1024 * 1024
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_UNSAFE_SUFFIXES = {
    "localhost",
    "local",
    "localdomain",
    "internal",
    "intranet",
    "corp",
    "home",
    "lan",
    "home.arpa",
    "onion",
    "invalid",
    "test",
    "example",
}


class BrowserEgressWorkerError(RuntimeError):
    """The unprivileged proxy worker did not establish a trusted lifecycle."""


class BrowserEgressWorkerProtocolError(BrowserEgressWorkerError):
    """A worker IPC frame was malformed, excessive, or internally inconsistent."""


class BrowserEgressWorkerTimeout(BrowserEgressWorkerError):
    """A bounded worker lifecycle deadline expired."""


def _account_lock_check(user: str) -> tuple[bool, str]:
    try:
        entries = Path("/etc/shadow").read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return False, f"cannot read local shadow database ({exc.errno})"
    matches = [entry.split(":", 2) for entry in entries if entry.startswith(f"{user}:")]
    if len(matches) != 1 or len(matches[0]) < 2:
        return False, "local shadow entry is missing or ambiguous"
    if not matches[0][1].startswith(("!", "*")):
        return False, "service account password is not locked"
    return True, "password=locked"


def _verify_worker_identity(expected_uid: int, expected_gid: int) -> tuple[int, int]:
    """Parent-side proof that IDs name the unique locked proxy account."""

    if (
        not isinstance(expected_uid, int)
        or isinstance(expected_uid, bool)
        or not 0 < expected_uid < 2**31
        or not isinstance(expected_gid, int)
        or isinstance(expected_gid, bool)
        or not 0 < expected_gid < 2**31
    ):
        raise BrowserEgressWorkerError("proxy worker IDs are outside the safe range")
    try:
        account = pwd.getpwnam(WORKER_USER)
        group = grp.getgrnam(WORKER_GROUP)
        vmm_account = pwd.getpwnam(VMM_USER)
        vmm_group = grp.getgrnam(VMM_GROUP)
        supplementary_groups = set(os.getgrouplist(WORKER_USER, account.pw_gid))
        other_uid_owners = {
            value.pw_name
            for value in pwd.getpwall()
            if value.pw_uid == expected_uid and value.pw_name != WORKER_USER
        }
        other_gid_owners = {
            value.gr_name
            for value in grp.getgrall()
            if value.gr_gid == expected_gid and value.gr_name != WORKER_GROUP
        }
    except (KeyError, OSError) as exc:
        raise BrowserEgressWorkerError(
            "dedicated proxy or VMM identity cannot be resolved"
        ) from exc

    forbidden_uids = {0, 65533, 65534}
    forbidden_gids = {0, 65533, 65534}
    try:
        forbidden_uids.add(pwd.getpwnam("nobody").pw_uid)
    except KeyError:
        pass
    for nobody_group in ("nobody", "nogroup"):
        try:
            forbidden_gids.add(grp.getgrnam(nobody_group).gr_gid)
        except KeyError:
            pass
    locked, _lock_detail = _account_lock_check(WORKER_USER)
    identity_values = {expected_uid, expected_gid}
    vmm_values = {vmm_account.pw_uid, vmm_group.gr_gid}
    valid = (
        account.pw_uid == expected_uid
        and account.pw_gid == expected_gid
        and group.gr_gid == expected_gid
        and expected_uid not in forbidden_uids
        and expected_gid not in forbidden_gids
        and not identity_values.intersection(vmm_values)
        and account.pw_dir == "/nonexistent"
        and Path(account.pw_shell).name in {"nologin", "false"}
        and supplementary_groups == {expected_gid}
        and not (set(group.gr_mem) - {WORKER_USER})
        and not other_uid_owners
        and not other_gid_owners
        and locked
    )
    if not valid:
        raise BrowserEgressWorkerError(
            "proxy worker IDs are not bound to the unique locked cindermote-proxy account"
        )
    return expected_uid, expected_gid


class _ProcessLike(Protocol):
    pid: int

    def kill(self) -> None: ...

    def poll(self) -> int | None: ...

    def terminate(self) -> None: ...

    def wait(self, timeout: float | None = None) -> int: ...


def _json_object(raw: bytes) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in items:
            if key in value:
                raise BrowserEgressWorkerProtocolError("duplicate IPC JSON key")
            value[key] = item
        return value

    def constant(_value: str) -> None:
        raise BrowserEgressWorkerProtocolError("non-finite IPC JSON number")

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_constant=constant,
        )
    except BrowserEgressWorkerProtocolError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrowserEgressWorkerProtocolError("invalid IPC JSON") from exc
    if not isinstance(value, dict):
        raise BrowserEgressWorkerProtocolError("IPC frame must be an object")
    return value


def _encode_frame(value: Mapping[str, Any], maximum: int) -> bytes:
    try:
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise BrowserEgressWorkerProtocolError("IPC value is not strict JSON") from exc
    if not payload or len(payload) > maximum:
        raise BrowserEgressWorkerProtocolError("IPC frame exceeds its byte limit")
    return _FRAME_HEADER.pack(len(payload)) + payload


def _remaining(deadline: float) -> float:
    value = deadline - time.monotonic()
    if value <= 0:
        raise BrowserEgressWorkerTimeout("worker IPC deadline expired")
    return value


def _write_all(fd: int, payload: bytes, deadline: float) -> None:
    offset = 0
    while offset < len(payload):
        _readable, writable, _exceptional = select.select(
            [], [fd], [], _remaining(deadline)
        )
        if not writable:
            raise BrowserEgressWorkerTimeout("worker IPC write timed out")
        try:
            count = os.write(fd, payload[offset : offset + 4096])
        except InterruptedError:
            continue
        except OSError as exc:
            raise BrowserEgressWorkerProtocolError("worker IPC write failed") from exc
        if count <= 0:
            raise BrowserEgressWorkerProtocolError("worker IPC write made no progress")
        offset += count


def _write_frame(fd: int, value: Mapping[str, Any], maximum: int, deadline: float) -> None:
    _write_all(fd, _encode_frame(value, maximum), deadline)


def _read_exact(fd: int, count: int, deadline: float) -> bytes:
    result = bytearray()
    while len(result) < count:
        readable, _writable, _exceptional = select.select(
            [fd], [], [], _remaining(deadline)
        )
        if not readable:
            raise BrowserEgressWorkerTimeout("worker IPC read timed out")
        try:
            chunk = os.read(fd, count - len(result))
        except InterruptedError:
            continue
        except OSError as exc:
            raise BrowserEgressWorkerProtocolError("worker IPC read failed") from exc
        if not chunk:
            raise BrowserEgressWorkerProtocolError("worker IPC closed early")
        result.extend(chunk)
    return bytes(result)


def _read_frame(fd: int, maximum: int, deadline: float) -> dict[str, Any]:
    header = _read_exact(fd, _FRAME_HEADER.size, deadline)
    (length,) = _FRAME_HEADER.unpack(header)
    if not 1 <= length <= maximum:
        raise BrowserEgressWorkerProtocolError("worker IPC length is invalid")
    return _json_object(_read_exact(fd, length, deadline))


def _bounded_timeout(value: float, *, name: str, maximum: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0.1 <= float(value) <= maximum
    ):
        raise BrowserEgressWorkerError(f"{name} is outside its fixed safety range")
    return float(value)


def _canonical_local_ip(
    value: Any,
    name: str,
    *,
    allow_link_local: bool = False,
) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or "%" in value:
        raise BrowserEgressWorkerError(f"{name} must be a plain IP literal")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise BrowserEgressWorkerError(f"{name} must be a plain IP literal") from exc
    if (
        address.is_unspecified
        or address.is_multicast
        or (address.is_link_local and not allow_link_local)
        or address.is_global
    ):
        raise BrowserEgressWorkerError(f"{name} must be a private endpoint")
    return address.compressed


def _expected_security_receipt(uid: int, gid: int) -> dict[str, Any]:
    return {
        "uid": uid,
        "gid": gid,
        "uids": [uid, uid, uid],
        "gids": [gid, gid, gid],
        "supplementary_groups": 0,
        "no_new_privs": True,
        "dumpable": False,
        "parent_death_signal": int(signal.SIGKILL),
        "parent_pid_bound": True,
        "capabilities_zero": True,
        "environment_entries": 0,
        "rlimits": {
            name: [limit, limit]
            for name, (_resource_name, limit) in sorted(RLIMITS.items())
        },
    }


def _validate_security_receipt(value: Any, *, uid: int, gid: int) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != SECURITY_KEYS:
        raise BrowserEgressWorkerProtocolError("worker security receipt shape changed")
    expected = _expected_security_receipt(uid, gid)
    if value != expected:
        raise BrowserEgressWorkerProtocolError("worker privilege drop is incomplete")
    return copy.deepcopy(expected)


def _validate_ready(
    value: Any,
    *,
    nonce: str,
    endpoint: tuple[str, int],
    worker_uid: int,
    worker_gid: int,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != READY_KEYS:
        detail = (
            f"keys={sorted(value)} code={value.get('code')}"
            if isinstance(value, dict)
            else f"type={type(value).__name__}"
        )
        raise BrowserEgressWorkerProtocolError(f"worker readiness shape changed ({detail})")
    if (
        value["type"] != "ready"
        or value["protocol_version"] != PROTOCOL_VERSION
        or value["nonce"] != nonce
        or value["endpoint"] != [endpoint[0], endpoint[1]]
    ):
        raise BrowserEgressWorkerProtocolError("worker readiness is not session-bound")
    return {
        "type": "ready",
        "protocol_version": PROTOCOL_VERSION,
        "nonce": nonce,
        "endpoint": [endpoint[0], endpoint[1]],
        "security": _validate_security_receipt(
            value["security"], uid=worker_uid, gid=worker_gid
        ),
    }


def _canonical_event_origin(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > MAX_EVENT_ORIGIN_BYTES
        or any(ord(character) <= 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise BrowserEgressWorkerProtocolError("worker event origin is invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise BrowserEgressWorkerProtocolError("worker event origin is invalid") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.hostname != parsed.hostname.lower()
    ):
        raise BrowserEgressWorkerProtocolError("worker event origin is not canonical")
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        pass
    else:
        raise BrowserEgressWorkerProtocolError("worker event origin cannot be an IP literal")
    hostname = parsed.hostname
    try:
        hostname.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise BrowserEgressWorkerProtocolError(
            "worker event origin hostname is not canonical IDNA"
        ) from exc
    labels = hostname.split(".")
    if (
        len(hostname) > 253
        or len(labels) < 2
        or hostname.endswith(".")
        or any(not _HOST_LABEL.fullmatch(label) for label in labels)
        or labels[-1].isdigit()
    ):
        raise BrowserEgressWorkerProtocolError("worker event hostname is invalid")
    for suffix in _UNSAFE_SUFFIXES:
        if hostname == suffix or hostname.endswith("." + suffix):
            raise BrowserEgressWorkerProtocolError(
                "worker event hostname is special-use"
            )
    if port is not None and not 1 <= port <= 65535:
        raise BrowserEgressWorkerProtocolError("worker event origin port is invalid")
    default_port = 80 if parsed.scheme == "http" else 443
    authority = hostname if port in {None, default_port} else f"{hostname}:{port}"
    canonical = f"{parsed.scheme}://{authority}"
    if canonical != value:
        raise BrowserEgressWorkerProtocolError("worker event origin is not canonical")
    return canonical


def _canonical_event_authority(value: Any) -> str:
    if (
        not isinstance(value, str)
        or value.count(":") != 1
        or any(character in value for character in "/?#@\\")
    ):
        raise BrowserEgressWorkerProtocolError(
            "worker CONNECT authority is invalid"
        )
    raw_host, raw_port = value.rsplit(":", 1)
    if not raw_host or not raw_port.isdigit():
        raise BrowserEgressWorkerProtocolError(
            "worker CONNECT authority is invalid"
        )
    port = int(raw_port)
    if not 1 <= port <= 65535:
        raise BrowserEgressWorkerProtocolError(
            "worker CONNECT authority port is invalid"
        )
    origin = _canonical_event_origin(
        f"https://{raw_host}" if port == 443 else f"https://{raw_host}:{port}"
    )
    hostname = urlsplit(origin).hostname
    if hostname is None:
        raise BrowserEgressWorkerProtocolError(
            "worker CONNECT authority hostname is invalid"
        )
    canonical = f"{hostname}:{port}"
    if canonical != value:
        raise BrowserEgressWorkerProtocolError(
            "worker CONNECT authority is not canonical"
        )
    return canonical


def _validate_event(value: Any, expected_sequence: int) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != EVENT_KEYS:
        raise BrowserEgressWorkerProtocolError("worker event shape changed")
    if value["sequence"] != expected_sequence or value["source"] != "egress":
        raise BrowserEgressWorkerProtocolError("worker event sequence/source is invalid")
    kind = value["kind"]
    disposition = value["disposition"]
    web_origin = value["web_origin"]
    connect_authority = value["connect_authority"]
    if kind == "telemetry_loss":
        if (
            web_origin is not None
            or connect_authority is not None
            or disposition != "observed"
        ):
            raise BrowserEgressWorkerProtocolError("telemetry-loss event is malformed")
        canonical_origin = None
        canonical_authority = None
    elif kind == "network_request":
        if disposition not in {"allowed", "blocked"}:
            raise BrowserEgressWorkerProtocolError("network event disposition is invalid")
        if (web_origin is None) == (connect_authority is None):
            raise BrowserEgressWorkerProtocolError(
                "network event must carry exactly one witness type"
            )
        canonical_origin = (
            None if web_origin is None else _canonical_event_origin(web_origin)
        )
        if canonical_origin is not None and not canonical_origin.startswith("http://"):
            raise BrowserEgressWorkerProtocolError(
                "proxy web-origin evidence must be plain HTTP"
            )
        canonical_authority = (
            None
            if connect_authority is None
            else _canonical_event_authority(connect_authority)
        )
    else:
        raise BrowserEgressWorkerProtocolError("worker event kind is invalid")
    return {
        "sequence": expected_sequence,
        "source": "egress",
        "kind": kind,
        "web_origin": canonical_origin,
        "connect_authority": canonical_authority,
        "disposition": disposition,
    }


def _bounded_uint(value: Any, name: str, maximum: int = MAX_COUNTER_VALUE) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= maximum
    ):
        raise BrowserEgressWorkerProtocolError(f"worker telemetry {name} is invalid")
    return value


def _validate_telemetry(value: Any, event_count: int) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != TELEMETRY_KEYS:
        raise BrowserEgressWorkerProtocolError("worker telemetry shape changed")
    for name in ("complete", "started", "closed", "event_overflow"):
        if not isinstance(value[name], bool):
            raise BrowserEgressWorkerProtocolError(f"worker telemetry {name} is invalid")
    normalized = {
        "complete": value["complete"],
        "started": value["started"],
        "closed": value["closed"],
        "event_overflow": value["event_overflow"],
        "inflight_events": _bounded_uint(value["inflight_events"], "inflight_events"),
        "active_connections": _bounded_uint(value["active_connections"], "active_connections"),
        "listener_rejections": _bounded_uint(value["listener_rejections"], "listener_rejections"),
        "connection_attempts": _bounded_uint(value["connection_attempts"], "connection_attempts"),
        "event_count": _bounded_uint(value["event_count"], "event_count", MAX_FINAL_EVENTS),
        "network_bytes": _bounded_uint(value["network_bytes"], "network_bytes", MAX_NETWORK_BYTES),
        "network_byte_limit": _bounded_uint(
            value["network_byte_limit"], "network_byte_limit", MAX_NETWORK_BYTES
        ),
    }
    if normalized["event_count"] != event_count:
        raise BrowserEgressWorkerProtocolError("worker event count disagrees with telemetry")
    if normalized["network_bytes"] > normalized["network_byte_limit"]:
        raise BrowserEgressWorkerProtocolError("worker byte accounting exceeds its limit")
    clean = (
        normalized["started"]
        and normalized["closed"]
        and not normalized["event_overflow"]
        and normalized["inflight_events"] == 0
        and normalized["active_connections"] == 0
        and normalized["listener_rejections"] == 0
    )
    if normalized["complete"] != clean:
        raise BrowserEgressWorkerProtocolError("worker completeness claim is inconsistent")
    return normalized


def _validate_final(value: Any, *, nonce: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not isinstance(value, dict) or set(value) != FINAL_KEYS:
        raise BrowserEgressWorkerProtocolError("worker final frame shape changed")
    if (
        value["type"] != "final"
        or value["protocol_version"] != PROTOCOL_VERSION
        or value["nonce"] != nonce
    ):
        raise BrowserEgressWorkerProtocolError("worker final frame is not session-bound")
    raw_events = value["events"]
    if not isinstance(raw_events, list) or len(raw_events) > MAX_FINAL_EVENTS:
        raise BrowserEgressWorkerProtocolError("worker final events are excessive")
    events = [_validate_event(event, index) for index, event in enumerate(raw_events)]
    telemetry = _validate_telemetry(value["telemetry"], len(events))
    return events, telemetry


def _failure_events() -> list[dict[str, Any]]:
    return [
        {
            "sequence": 0,
            "source": "egress",
            "kind": "telemetry_loss",
            "web_origin": None,
            "connect_authority": None,
            "disposition": "observed",
        }
    ]


def _failure_telemetry() -> dict[str, Any]:
    return {
        "complete": False,
        "started": False,
        "closed": True,
        "event_overflow": True,
        "inflight_events": 0,
        "active_connections": 0,
        "listener_rejections": 0,
        "connection_attempts": 0,
        "event_count": 1,
        "network_bytes": 0,
        "network_byte_limit": 0,
    }


def _read_trusted_proxy_sources() -> dict[str, tuple[str, bytes]]:
    """Read bounded trusted source in the root child without executing it.

    The workspace may sit below a private home directory that UID 65533 cannot
    traverse.  Holding immutable source bytes lets module execution still occur
    only after the irreversible privilege drop, without widening directory
    permissions or copying code into a writable staging area.
    """

    result: dict[str, tuple[str, bytes]] = {}
    for module_name, path in _TRUSTED_SOURCE_PATHS.items():
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            raise BrowserEgressWorkerError("trusted proxy source cannot be opened") from exc
        try:
            metadata = os.fstat(fd)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_mode & 0o022
                or not 1 <= metadata.st_size <= _MAX_TRUSTED_SOURCE_BYTES
            ):
                raise BrowserEgressWorkerError("trusted proxy source metadata is unsafe")
            chunks: list[bytes] = []
            remaining = metadata.st_size
            while remaining:
                chunk = os.read(fd, min(remaining, 64 * 1024))
                if not chunk:
                    raise BrowserEgressWorkerError("trusted proxy source ended early")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(fd, 1):
                raise BrowserEgressWorkerError("trusted proxy source changed while read")
            source = b"".join(chunks)
        finally:
            os.close(fd)
        result[module_name] = (str(path), source)
    return result


def _execute_proxy_sources_after_drop(
    sources: Mapping[str, tuple[str, bytes]],
) -> Callable[..., Any]:
    """Compile and execute the proxy modules in the unprivileged child only."""

    if set(sources) != set(_TRUSTED_SOURCE_PATHS):
        raise BrowserEgressWorkerError("trusted proxy source set changed")
    protected_names = {
        "mote",
        "mote.browser_contract",
        "broker",
        "broker.browser_egress_proxy",
    }
    if protected_names & set(sys.modules):
        raise BrowserEgressWorkerError("proxy module was loaded before privilege drop")

    mote_package = types.ModuleType("mote")
    mote_package.__package__ = "mote"
    mote_package.__path__ = []  # type: ignore[attr-defined]
    broker_package = types.ModuleType("broker")
    broker_package.__package__ = "broker"
    broker_package.__path__ = []  # type: ignore[attr-defined]
    sys.modules["mote"] = mote_package
    sys.modules["broker"] = broker_package
    loaded: list[str] = []
    try:
        for module_name in ("mote.browser_contract", "broker.browser_egress_proxy"):
            filename, source = sources[module_name]
            module = types.ModuleType(module_name)
            module.__file__ = filename
            module.__package__ = module_name.rpartition(".")[0]
            sys.modules[module_name] = module
            loaded.append(module_name)
            code = compile(source, filename, "exec", dont_inherit=True, optimize=0)
            exec(code, module.__dict__)
        proxy_class = sys.modules["broker.browser_egress_proxy"].__dict__.get(
            "BrowserEgressProxy"
        )
        if not isinstance(proxy_class, type):
            raise BrowserEgressWorkerError("trusted proxy class is missing")
        return proxy_class
    except BaseException:
        for name in reversed(loaded):
            sys.modules.pop(name, None)
        sys.modules.pop("mote", None)
        sys.modules.pop("broker", None)
        raise


class _SecurityOps:
    """Small injectable syscall surface used to test privilege-drop ordering."""

    def clear_environment(self) -> None:
        os.environ.clear()

    def set_no_new_privs(self) -> None:
        libc = ctypes.CDLL(None, use_errno=True)
        result = libc.prctl(38, 1, 0, 0, 0)  # PR_SET_NO_NEW_PRIVS
        if result != 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))

    def get_no_new_privs(self) -> bool:
        libc = ctypes.CDLL(None, use_errno=True)
        result = libc.prctl(39, 0, 0, 0, 0)  # PR_GET_NO_NEW_PRIVS
        if result < 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
        return result == 1

    def set_dumpable_false(self) -> None:
        libc = ctypes.CDLL(None, use_errno=True)
        result = libc.prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE
        if result != 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))

    def get_dumpable(self) -> bool:
        libc = ctypes.CDLL(None, use_errno=True)
        result = libc.prctl(3, 0, 0, 0, 0)  # PR_GET_DUMPABLE
        if result < 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
        return result == 1

    def set_parent_death_signal(self, value: int) -> None:
        libc = ctypes.CDLL(None, use_errno=True)
        result = libc.prctl(1, value, 0, 0, 0)  # PR_SET_PDEATHSIG
        if result != 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))

    def get_parent_death_signal(self) -> int:
        libc = ctypes.CDLL(None, use_errno=True)
        value = ctypes.c_int(0)
        result = libc.prctl(2, ctypes.byref(value), 0, 0, 0)  # PR_GET_PDEATHSIG
        if result != 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
        return int(value.value)

    def get_parent_pid(self) -> int:
        return os.getppid()

    def set_limit(self, resource_name: int, value: int) -> None:
        resource.setrlimit(resource_name, (value, value))

    def get_limit(self, resource_name: int) -> tuple[int, int]:
        return resource.getrlimit(resource_name)

    def set_groups(self, groups: list[int]) -> None:
        os.setgroups(groups)

    def set_gid(self, gid: int) -> None:
        os.setresgid(gid, gid, gid)

    def set_uid(self, uid: int) -> None:
        os.setresuid(uid, uid, uid)

    def get_groups(self) -> list[int]:
        return os.getgroups()

    def get_gid(self) -> int:
        return os.getgid()

    def get_uid(self) -> int:
        return os.getuid()

    def get_gids(self) -> tuple[int, int, int]:
        return os.getresgid()

    def get_uids(self) -> tuple[int, int, int]:
        return os.getresuid()

    def capabilities_zero(self) -> bool:
        try:
            lines = Path("/proc/self/status").read_text(encoding="ascii").splitlines()
        except OSError:
            return False
        values = {
            key: int(value.strip(), 16)
            for line in lines
            for key, marker in (
                ("effective", "CapEff:"),
                ("permitted", "CapPrm:"),
                ("ambient", "CapAmb:"),
            )
            if line.startswith(marker)
            for value in (line[len(marker) :],)
        }
        return set(values) == {"effective", "permitted", "ambient"} and not any(
            values.values()
        )

    def environment_count(self) -> int:
        return len(os.environ)

    def umask(self, value: int) -> None:
        os.umask(value)

    def chdir_root(self) -> None:
        os.chdir("/")


def _apply_worker_sandbox(
    *,
    uid: int,
    gid: int,
    expected_parent_pid: int | None = None,
    ops: _SecurityOps | None = None,
) -> dict[str, Any]:
    """Apply and attest irreversible child restrictions before proxy import."""

    if uid == 0 or gid == 0:
        raise BrowserEgressWorkerError("proxy worker cannot retain root identity")
    system = ops or _SecurityOps()
    parent_pid = system.get_parent_pid()
    expected_parent = parent_pid if expected_parent_pid is None else expected_parent_pid
    if parent_pid != expected_parent or expected_parent <= 1:
        raise BrowserEgressWorkerError("proxy worker parent identity changed")
    system.clear_environment()
    system.set_no_new_privs()
    for _name, (resource_name, limit) in RLIMITS.items():
        system.set_limit(resource_name, limit)
    # Supplementary groups must be removed while CAP_SETGID is still present.
    system.set_groups([])
    system.set_gid(gid)
    system.set_uid(uid)
    system.set_dumpable_false()
    # Credential changes clear PDEATHSIG, so bind it only after the final UID
    # transition and re-check the parent to close the fork/exec race.
    system.set_parent_death_signal(signal.SIGKILL)
    parent_bound = system.get_parent_pid() == expected_parent
    if not parent_bound:
        raise BrowserEgressWorkerError("proxy worker parent exited during sandboxing")
    system.umask(0o077)
    system.chdir_root()

    receipt = {
        "uid": system.get_uid(),
        "gid": system.get_gid(),
        "uids": list(system.get_uids()),
        "gids": list(system.get_gids()),
        "supplementary_groups": len(system.get_groups()),
        "no_new_privs": system.get_no_new_privs(),
        "dumpable": system.get_dumpable(),
        "parent_death_signal": system.get_parent_death_signal(),
        "parent_pid_bound": parent_bound,
        "capabilities_zero": system.capabilities_zero(),
        "environment_entries": system.environment_count(),
        "rlimits": {
            name: list(system.get_limit(resource_name))
            for name, (resource_name, _limit) in sorted(RLIMITS.items())
        },
    }
    # Use the same strict verifier as the root parent.  Any incomplete drop
    # exits before the parser module is imported or a listener is created.
    return _validate_security_receipt(receipt, uid=uid, gid=gid)


def _wall_clock_from_config(config: Mapping[str, Any]) -> int:
    request = config.get("request")
    if not isinstance(request, dict):
        raise BrowserEgressWorkerProtocolError("worker request is missing")
    budgets = request.get("budgets")
    if not isinstance(budgets, dict):
        raise BrowserEgressWorkerProtocolError("worker request budgets are missing")
    value = budgets.get("wall_clock_sec")
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 60:
        raise BrowserEgressWorkerProtocolError("worker wall-clock budget is invalid")
    return value


def _validate_child_config(value: Any) -> dict[str, Any]:
    keys = {"type", "protocol_version", "nonce", "request", "bind_host", "bind_port", "allowed_client_ip"}
    if not isinstance(value, dict) or set(value) != keys:
        raise BrowserEgressWorkerProtocolError("worker start frame shape changed")
    nonce = value["nonce"]
    if (
        value["type"] != "start"
        or value["protocol_version"] != PROTOCOL_VERSION
        or not isinstance(nonce, str)
        or len(nonce) != 64
        or any(character not in "0123456789abcdef" for character in nonce)
    ):
        raise BrowserEgressWorkerProtocolError("worker start frame is invalid")
    bind_host = _canonical_local_ip(
        value["bind_host"], "bind_host", allow_link_local=True
    )
    allowed_client = _canonical_local_ip(value["allowed_client_ip"], "allowed_client_ip")
    port = value["bind_port"]
    if not isinstance(port, int) or isinstance(port, bool) or not 1024 <= port <= 65535:
        raise BrowserEgressWorkerProtocolError("worker bind port is invalid")
    if not isinstance(value["request"], dict):
        raise BrowserEgressWorkerProtocolError("worker request must be an object")
    normalized = {
        "type": "start",
        "protocol_version": PROTOCOL_VERSION,
        "nonce": nonce,
        "request": copy.deepcopy(value["request"]),
        "bind_host": bind_host,
        "bind_port": port,
        "allowed_client_ip": allowed_client,
    }
    _wall_clock_from_config(normalized)
    return normalized


def _child_proxy_loop(
    control_fd: int,
    status_fd: int,
    security: dict[str, Any],
    *,
    proxy_factory: Callable[..., Any],
) -> int:
    """Run the already-unprivileged framed worker protocol."""

    proxy: Any | None = None
    nonce = "0" * 64
    ready_sent = False
    failed = False
    try:
        config = _validate_child_config(
            _read_frame(
                control_fd,
                MAX_CONFIG_FRAME_BYTES,
                time.monotonic() + READY_TIMEOUT_SEC,
            )
        )
        nonce = config["nonce"]
        proxy = proxy_factory(
            config["request"],
            bind_host=config["bind_host"],
            bind_port=config["bind_port"],
            allowed_client_ip=config["allowed_client_ip"],
        )
        endpoint = proxy.start()
        if endpoint != (config["bind_host"], config["bind_port"]):
            raise BrowserEgressWorkerProtocolError("proxy bound an unexpected endpoint")
        _write_frame(
            status_fd,
            {
                "type": "ready",
                "protocol_version": PROTOCOL_VERSION,
                "nonce": nonce,
                "endpoint": [endpoint[0], endpoint[1]],
                "security": security,
            },
            MAX_STATUS_FRAME_BYTES,
            time.monotonic() + READY_TIMEOUT_SEC,
        )
        ready_sent = True
        stop_deadline = time.monotonic() + _wall_clock_from_config(config) + STOP_TIMEOUT_SEC
        command = _read_frame(control_fd, MAX_CONFIG_FRAME_BYTES, stop_deadline)
        if set(command) != {"type", "protocol_version", "nonce"} or command != {
            "type": "stop",
            "protocol_version": PROTOCOL_VERSION,
            "nonce": nonce,
        }:
            failed = True
    except BaseException:
        failed = True
    finally:
        if proxy is not None:
            try:
                proxy.stop()
            except BaseException:
                failed = True

    if not ready_sent:
        try:
            _write_frame(
                status_fd,
                {"type": "error", "protocol_version": PROTOCOL_VERSION, "code": "startup_failed"},
                MAX_STATUS_FRAME_BYTES,
                time.monotonic() + 0.5,
            )
        except BaseException:
            pass
        return 1

    if not failed and proxy is not None:
        try:
            events = proxy.browser_events_snapshot()
            telemetry = proxy.telemetry_snapshot()
            # Validate before sending so the child cannot accidentally emit a
            # larger or looser shape than the root parent accepts.
            events, telemetry = _validate_final(
                {
                    "type": "final",
                    "protocol_version": PROTOCOL_VERSION,
                    "nonce": nonce,
                    "events": events,
                    "telemetry": telemetry,
                },
                nonce=nonce,
            )
        except BaseException:
            failed = True
    if failed:
        events = _failure_events()
        telemetry = _failure_telemetry()
    try:
        _write_frame(
            status_fd,
            {
                "type": "final",
                "protocol_version": PROTOCOL_VERSION,
                "nonce": nonce,
                "events": events,
                "telemetry": telemetry,
            },
            MAX_STATUS_FRAME_BYTES,
            time.monotonic() + STOP_TIMEOUT_SEC,
        )
    except BaseException:
        return 1
    return 1 if failed else 0


def _child_entry(
    control_fd: int,
    status_fd: int,
    expected_parent_pid: int,
    worker_uid: int,
    worker_gid: int,
) -> int:
    security: dict[str, Any]
    try:
        # Read trusted bytes while root, but do not compile/execute the parser.
        # The workspace may be below a mode-0700 operator home.
        _verify_worker_identity(worker_uid, worker_gid)
        sources = _read_trusted_proxy_sources()
        security = _apply_worker_sandbox(
            uid=worker_uid,
            gid=worker_gid,
            expected_parent_pid=expected_parent_pid,
        )
        sys.dont_write_bytecode = True
        # Compilation and module execution happen only after the security
        # receipt passed strict validation.
        BrowserEgressProxy = _execute_proxy_sources_after_drop(sources)
    except BaseException:
        try:
            _write_frame(
                status_fd,
                {"type": "error", "protocol_version": PROTOCOL_VERSION, "code": "sandbox_failed"},
                MAX_STATUS_FRAME_BYTES,
                time.monotonic() + 0.5,
            )
        except BaseException:
            pass
        return 1
    return _child_proxy_loop(
        control_fd,
        status_fd,
        security,
        proxy_factory=BrowserEgressProxy,
    )


class BrowserEgressWorker:
    """Root-side handle for the unprivileged browser egress process.

    Its public lifecycle intentionally matches ``BrowserEgressProxy`` so the
    Firecracker runtime can replace the unsafe in-process factory directly.
    """

    def __init__(
        self,
        request: Mapping[str, Any],
        *,
        bind_host: str,
        allowed_client_ip: str,
        worker_uid: int,
        worker_gid: int,
        bind_port: int = 3128,
        ready_timeout_sec: float = READY_TIMEOUT_SEC,
        stop_timeout_sec: float = STOP_TIMEOUT_SEC,
    ) -> None:
        self._bind_host = _canonical_local_ip(
            bind_host, "bind_host", allow_link_local=True
        )
        self._allowed_client_ip = _canonical_local_ip(
            allowed_client_ip, "allowed_client_ip"
        )
        if (
            not isinstance(bind_port, int)
            or isinstance(bind_port, bool)
            or not 1024 <= bind_port <= 65535
        ):
            raise BrowserEgressWorkerError("bind_port must be in 1024..65535")
        self._bind_port = bind_port
        if (
            not isinstance(worker_uid, int)
            or isinstance(worker_uid, bool)
            or not 0 < worker_uid < 2**31
            or not isinstance(worker_gid, int)
            or isinstance(worker_gid, bool)
            or not 0 < worker_gid < 2**31
        ):
            raise BrowserEgressWorkerError("proxy worker IDs are outside the safe range")
        self._worker_uid = worker_uid
        self._worker_gid = worker_gid
        self._ready_timeout = _bounded_timeout(
            ready_timeout_sec, name="ready_timeout_sec", maximum=15.0
        )
        self._stop_timeout = _bounded_timeout(
            stop_timeout_sec, name="stop_timeout_sec", maximum=15.0
        )
        try:
            encoded_request = json.dumps(
                request,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
            normalized_request = _json_object(encoded_request.encode("ascii"))
        except (TypeError, ValueError, BrowserEgressWorkerProtocolError) as exc:
            raise BrowserEgressWorkerError("browser request is not strict JSON") from exc
        self._request = normalized_request
        _wall_clock_from_config({"request": self._request})

        self._lock = threading.Lock()
        self._lifecycle_lock = threading.Lock()
        self._state = "new"
        self._process: _ProcessLike | None = None
        self._control_fd: int | None = None
        self._status_fd: int | None = None
        self._nonce: str | None = None
        self._ready_receipt: dict[str, Any] | None = None
        self._purge_verified = False
        self._pending_purge_verified = False
        self._events = _failure_events()
        self._telemetry = _failure_telemetry()

    @property
    def bind_address(self) -> tuple[str, int]:
        return self._bind_host, self._bind_port

    @property
    def allowed_client_ip(self) -> str:
        return self._allowed_client_ip

    @property
    def readiness_receipt(self) -> dict[str, Any] | None:
        with self._lock:
            return copy.deepcopy(self._ready_receipt)

    @property
    def purge_verified(self) -> bool:
        """Whether teardown independently reaped the worker and emptied its group."""

        with self._lock:
            return self._purge_verified

    def _spawn(self, control_read: int, status_write: int) -> _ProcessLike:
        process = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                str(_THIS_FILE),
                "--child",
                str(control_read),
                str(status_write),
                str(os.getpid()),
                str(self._worker_uid),
                str(self._worker_gid),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd="/",
            env={},
            close_fds=True,
            pass_fds=(control_read, status_write),
            start_new_session=True,
        )
        # Marker used by teardown to kill and audit the entire isolated process
        # group, including any unexpected descendant of the parser worker.
        setattr(process, "_cindermote_process_group", True)
        return process

    def _verify_identity(self) -> tuple[int, int]:
        return _verify_worker_identity(self._worker_uid, self._worker_gid)

    def start(self) -> tuple[str, int]:
        with self._lifecycle_lock:
            return self._start_impl()

    def _start_impl(self) -> tuple[str, int]:
        # Do this immediately before spawning; constructor-supplied integers
        # are never authority for a privilege transition.
        self._verify_identity()
        with self._lock:
            if self._state != "new":
                raise BrowserEgressWorkerError("proxy worker can only start once")
            self._state = "starting"
        control_read, control_write = os.pipe2(os.O_CLOEXEC)
        status_read, status_write = os.pipe2(os.O_CLOEXEC)
        process: _ProcessLike | None = None
        try:
            process = self._spawn(control_read, status_write)
            os.close(control_read)
            control_read = -1
            os.close(status_write)
            status_write = -1
            nonce = secrets.token_hex(32)
            deadline = time.monotonic() + self._ready_timeout
            _write_frame(
                control_write,
                {
                    "type": "start",
                    "protocol_version": PROTOCOL_VERSION,
                    "nonce": nonce,
                    "request": self._request,
                    "bind_host": self._bind_host,
                    "bind_port": self._bind_port,
                    "allowed_client_ip": self._allowed_client_ip,
                },
                MAX_CONFIG_FRAME_BYTES,
                deadline,
            )
            receipt = _validate_ready(
                _read_frame(status_read, MAX_STATUS_FRAME_BYTES, deadline),
                nonce=nonce,
                endpoint=self.bind_address,
                worker_uid=self._worker_uid,
                worker_gid=self._worker_gid,
            )
            if process.poll() is not None:
                raise BrowserEgressWorkerError("proxy worker exited during readiness")
        except BaseException:
            for fd in (control_read, control_write, status_read, status_write):
                if fd >= 0:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
            purge_verified = (
                self._terminate_process(process) if process is not None else False
            )
            with self._lock:
                self._pending_purge_verified = purge_verified
                self._state = "failed"
            raise
        with self._lock:
            self._process = process
            self._control_fd = control_write
            self._status_fd = status_read
            self._nonce = nonce
            self._ready_receipt = receipt
            self._state = "running"
        return self.bind_address

    def _process_group_exists(self, process: _ProcessLike) -> bool:
        if not bool(getattr(process, "_cindermote_process_group", False)):
            return False
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    def _wait_process_group_empty(
        self,
        process: _ProcessLike,
        timeout: float = PURGE_RECHECK_SEC,
    ) -> bool:
        if not bool(getattr(process, "_cindermote_process_group", False)):
            return False
        deadline = time.monotonic() + timeout
        while True:
            if not self._process_group_exists(process):
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)

    def _terminate_process(self, process: _ProcessLike) -> bool:
        """Boundedly revoke, reap, and independently empty the worker group."""

        process_group = bool(
            getattr(process, "_cindermote_process_group", False)
        )
        if process.poll() is None:
            try:
                if process_group:
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        process.terminate()
                else:
                    process.terminate()
                process.wait(timeout=KILL_GRACE_SEC)
            except BaseException:
                pass
        # Kill the group even after the leader exits. A clean leader receipt
        # cannot authorize a same-group descendant to survive teardown.
        if process_group:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        elif process.poll() is None:
            try:
                process.kill()
            except BaseException:
                pass
        try:
            process.wait(timeout=KILL_GRACE_SEC)
        except BaseException:
            pass
        leader_reaped = process.poll() is not None
        group_empty = self._wait_process_group_empty(process)
        return leader_reaped and group_empty

    def stop(self) -> None:
        with self._lifecycle_lock:
            self._stop_impl()

    def _stop_impl(self) -> None:
        with self._lock:
            if self._state == "stopped":
                return
            if self._state == "failed":
                self._purge_verified = self._pending_purge_verified
                return
            if self._state == "new":
                self._state = "stopped"
                return
            process = self._process
            control_fd = self._control_fd
            status_fd = self._status_fd
            nonce = self._nonce
            self._state = "stopping"
        valid_final = False
        purge_verified = False
        descendants_observed = False
        events = _failure_events()
        telemetry = _failure_telemetry()
        deadline = time.monotonic() + self._stop_timeout
        try:
            if process is None or control_fd is None or status_fd is None or nonce is None:
                raise BrowserEgressWorkerProtocolError("worker lifecycle state is incomplete")
            _write_frame(
                control_fd,
                {
                    "type": "stop",
                    "protocol_version": PROTOCOL_VERSION,
                    "nonce": nonce,
                },
                MAX_CONFIG_FRAME_BYTES,
                deadline,
            )
            events, telemetry = _validate_final(
                _read_frame(status_fd, MAX_STATUS_FRAME_BYTES, deadline),
                nonce=nonce,
            )
            exit_code = process.wait(timeout=_remaining(deadline))
            if exit_code != 0:
                raise BrowserEgressWorkerError("proxy worker exited uncleanly")
            descendants_observed = self._process_group_exists(process)
            if descendants_observed:
                raise BrowserEgressWorkerError(
                    "proxy worker left a descendant process"
                )
            valid_final = True
        except BaseException:
            valid_final = False
        finally:
            if process is not None:
                leader_was_running = process.poll() is None
                purge_verified = self._terminate_process(process)
                if leader_was_running or descendants_observed:
                    valid_final = False
            for fd in (control_fd, status_fd):
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
        with self._lock:
            self._events = events if valid_final else _failure_events()
            self._telemetry = telemetry if valid_final else _failure_telemetry()
            self._control_fd = None
            self._status_fd = None
            self._purge_verified = purge_verified
            self._pending_purge_verified = purge_verified
            self._state = "stopped" if valid_final else "failed"

    def browser_events_snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(self._events)

    def telemetry_snapshot(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._telemetry)

    def __enter__(self) -> "BrowserEgressWorker":
        self.start()
        return self

    def __exit__(self, _type: Any, _value: Any, _traceback: Any) -> None:
        self.stop()


def _main(argv: list[str]) -> int:
    if len(argv) != 6 or argv[0] != "--child":
        return 2
    try:
        control_fd = int(argv[1], 10)
        status_fd = int(argv[2], 10)
        expected_parent_pid = int(argv[3], 10)
        worker_uid = int(argv[4], 10)
        worker_gid = int(argv[5], 10)
    except ValueError:
        return 2
    if (
        control_fd < 3
        or status_fd < 3
        or control_fd == status_fd
        or expected_parent_pid <= 1
        or not 0 < worker_uid < 2**31
        or not 0 < worker_gid < 2**31
    ):
        return 2
    try:
        return _child_entry(
            control_fd,
            status_fd,
            expected_parent_pid,
            worker_uid,
            worker_gid,
        )
    finally:
        for fd in (control_fd, status_fd):
            try:
                os.close(fd)
            except OSError:
                pass


__all__ = [
    "BrowserEgressWorker",
    "BrowserEgressWorkerError",
    "BrowserEgressWorkerProtocolError",
    "BrowserEgressWorkerTimeout",
    "PROTOCOL_VERSION",
    "WORKER_GROUP",
    "WORKER_USER",
]


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
