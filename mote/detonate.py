#!/usr/bin/env python3
"""Cindermote S0-S4 detonation orchestrator.

Artifacts execute only after namespace setup, tmpfs/overlay construction,
chroot, capability drop, ptrace registration, and seccomp installation. The
host process alone derives findings, applies policy, verifies purge, and signs
the receipt.
"""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import errno
import hashlib
import json
import os
import re
import resource
import selectors
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import sysconfig
import tarfile
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any


THIS_FILE = Path(__file__).resolve()
PROJECT_DIR = THIS_FILE.parents[1]
WORKSPACE_DIR = PROJECT_DIR.parent
for import_root in (PROJECT_DIR, WORKSPACE_DIR):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from cindermote.broker.broker import CapabilityBroker, OutwardReportSchemaError
from cindermote.gate.policy_gate import apply_scoring_matrix
from cindermote.observer.detectors import (
    DetectorEngine,
    RULES,
    make_event,
    scan_instruction_patterns,
    scan_tool_description,
)
from cindermote.observer.ptracer import (
    HostTracer,
    WAIT_WALL,
    install_seccomp,
    request_tracing,
    write_seccomp_blob,
)
from cindermote.observer.receipt import (
    create_receipt,
    required_isolation_controls,
    sha256_file,
    write_receipt,
)
from cindermote.mote.browser_contract import make_probe_request, origin_for_url, validate_probe_request
from cindermote.mote.firecracker_runtime import preflight_firecracker, run_browser_probe


POLICY_PATH = PROJECT_DIR / "policy" / "hotcell-policy.json"
SNAPSHOT_PATH = PROJECT_DIR / "policy" / "golden-snapshot.tar.gz"
SNAPSHOT_MANIFEST_PATH = PROJECT_DIR / "policy" / "golden-snapshot.manifest"
SECCOMP_BLOB_PATH = PROJECT_DIR / "mote" / "seccomp_filter.bpf"
OVERRIDE_PATH = PROJECT_DIR / "gate" / "override.json"
OBSERVER_KEY_PATH = PROJECT_DIR / ".observer_key"
RECEIPTS_DIR = PROJECT_DIR / "receipts"
QUARANTINE_DIR = PROJECT_DIR / "quarantine"
ALERTS_DIR = PROJECT_DIR / "alerts"
CANARY_TEMPLATES_DIR = PROJECT_DIR / "canaries"

VALID_ARTIFACT_TYPES = {
    "mcp-server",
    "tool-definition",
    "skill-md",
    "python-script",
    "shell-script",
    "browser-probe",
}

# mount(2) flags
MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_REMOUNT = 32
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1 << 18

MCL_CURRENT = 1
MCL_FUTURE = 2
LINUX_CAPABILITY_VERSION_3 = 0x20080522
LEGACY_CGROUP_ROOT = Path("/sys/fs/cgroup/cindermote")
READINESS_PROTOCOL = "cindermote-sandbox-ready-v1"
CGROUP_LAUNCH_TOKEN = b"cindermote-cgroup-ready-v1\n"
SANDBOX_ADMISSION_TOKEN = b"1"

libc = ctypes.CDLL(None, use_errno=True)


class SnapshotIntegrityError(RuntimeError):
    pass


class IsolationSetupError(RuntimeError):
    pass


class CgroupOperationError(IsolationSetupError):
    """Bounded host-owned cgroup failure evidence."""

    _STAGES = {
        "create_root",
        "create_job",
        "write_cpu_max",
        "write_memory_max",
        "write_memory_swap_max",
        "write_pids_max",
        "join_wrapper",
        "verify_wrapper_membership",
        "verify_wrapper_identity",
        "release_wrapper",
    }

    def __init__(self, stage: str, error: OSError | int) -> None:
        self.stage = stage if stage in self._STAGES else "verify_wrapper_identity"
        number = error if isinstance(error, int) else error.errno
        self.errno = number if isinstance(number, int) and number > 0 else errno.EIO
        super().__init__(f"{self.stage}:{self.errno}")

    def evidence(self) -> dict[str, int | str]:
        return {"stage": self.stage, "errno": self.errno}


class SandboxIdentityError(IsolationSetupError):
    """A bounded reason why host evidence did not admit a sandbox identity."""

    _STAGES = {
        "readiness_absent",
        "readiness_not_ready",
        "readiness_credentials_missing",
        "readiness_identity_malformed",
        "readiness_status_malformed",
        "readiness_pid_mismatch",
        "readiness_start_time_mismatch",
        "sandbox_process_missing",
        "sandbox_pidfd_open",
        "sandbox_pidfd_stop",
        "sandbox_not_stopped",
        "sandbox_ancestry_mismatch",
        "sandbox_cgroup_mismatch",
        "sandbox_process_group_mismatch",
        "sandbox_session_mismatch",
        "wrapper_process_missing",
        "wrapper_identity_changed",
        "wrapper_exited",
        "wrapper_process_group_mismatch",
        "wrapper_session_mismatch",
        "tracer_pid_mismatch",
    }

    def __init__(self, stage: str) -> None:
        self.stage = stage if stage in self._STAGES else "readiness_identity_malformed"
        super().__init__(self.stage)


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    state: str
    parent_pid: int
    process_group: int
    session: int
    start_time_ticks: int


@dataclass(frozen=True)
class ControlMessage:
    status: dict[str, Any]
    sender_pid: int | None
    sender_uid: int | None
    sender_gid: int | None
    credentials_valid: bool


@dataclass
class SandboxAdmission:
    pid: int
    start_time_ticks: int
    pidfd: int

    def close(self) -> None:
        if self.pidfd >= 0:
            try:
                os.close(self.pidfd)
            except OSError:
                pass
            self.pidfd = -1


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _json_read(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def load_policy(policy_json: str | Path | dict | None = None) -> dict:
    if policy_json is None:
        policy = _json_read(POLICY_PATH)
    elif isinstance(policy_json, dict):
        policy = json.loads(json.dumps(policy_json))
    else:
        policy = _json_read(Path(policy_json))
    budgets = policy.get("budgets")
    if not isinstance(budgets, dict):
        raise ValueError("policy.budgets is required")
    for name in ("wall_clock_sec", "cpu_vcpu", "ram_mib", "pids", "max_output_bytes"):
        if not isinstance(budgets.get(name), int) or budgets[name] <= 0:
            raise ValueError(f"invalid policy budget: {name}")
    return policy


def _policy_hash(policy: dict) -> str:
    payload = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _canonical_hash(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _write_private_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    payload = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(descriptor, payload.encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)


def _browser_destination_labels(events: Any) -> dict[str, list[str]]:
    """Reduce typed v2 network events to unambiguous receipt labels."""

    destinations: dict[str, set[str]] = {}
    for event in events if isinstance(events, list) else []:
        if not isinstance(event, dict) or event.get("kind") != "network_request":
            continue
        disposition = event.get("disposition")
        source = event.get("source")
        if disposition not in {"allowed", "blocked"}:
            continue
        web_origin = event.get("web_origin")
        connect_authority = event.get("connect_authority")
        if (
            source == "cdp"
            and isinstance(web_origin, str)
            and connect_authority is None
        ):
            destination = web_origin
            label = f"browser_cdp_web_origin_{disposition}"
        elif (
            source == "egress"
            and isinstance(web_origin, str)
            and connect_authority is None
        ):
            destination = web_origin
            label = f"proxy_http_origin_{disposition}"
        elif (
            source == "egress"
            and web_origin is None
            and isinstance(connect_authority, str)
        ):
            destination = connect_authority
            label = f"proxy_connect_authority_{disposition}"
        else:
            continue
        destinations.setdefault(destination, set()).add(label)
    return {
        destination: sorted(labels)
        for destination, labels in sorted(destinations.items())
    }


def detonate_browser_probe(
    probe_request: dict[str, Any],
    policy_json: str | Path | dict | None = None,
    *,
    submitted_by: str = "local-cli",
    artifact_sha256: str | None = None,
) -> dict:
    """Execute one passive browser probe with independent network witnesses.

    CDP reports web origins. The host proxy reports plain-HTTP origins or
    HTTPS CONNECT authorities. Firecracker is mandatory for this artifact
    type; a failed prerequisite or VM start raises instead of silently
    selecting the namespace runner.
    """

    policy = load_policy(policy_json)
    request = validate_probe_request(probe_request)
    policy_limits = policy.get("browser_budgets", {})
    for name, value in request["budgets"].items():
        limit = policy_limits.get(name)
        if not isinstance(limit, int) or value > limit:
            raise ValueError(f"browser budget exceeds policy ceiling: {name}")

    received_at = _utc_now()
    result = run_browser_probe(request)
    reduction = result.reduction
    findings = list(reduction.get("findings", []))
    runtime_admitted = result.runtime.get("admitted") is True
    if not runtime_admitted:
        findings.append(
            {"finding_id": "firecracker_runtime_failure", "count": 1, "severity": "CRITICAL"}
        )
    if not result.purge.get("verified_externally"):
        findings.append({"finding_id": "purge_failure", "count": 1, "severity": "CRITICAL"})

    counts: dict[str, int] = {}
    severities: dict[str, str] = {}
    for finding in findings:
        finding_id = finding.get("finding_id")
        count = finding.get("count")
        severity = finding.get("severity")
        if not isinstance(finding_id, str) or finding_id not in RULES:
            finding_id = "firecracker_runtime_failure"
            count = 1
            severity = "CRITICAL"
        if not isinstance(count, int) or count < 1:
            count = 1
        counts[finding_id] = counts.get(finding_id, 0) + count
        severities[finding_id] = severity if severity in {"HIGH", "CRITICAL"} else RULES[finding_id][1]

    outward_evidence = [
        {"tap_category": RULES[rule_id][0], "rule_id": rule_id, "count": count}
        for rule_id, count in sorted(counts.items())
    ]
    if any(severities[rule_id] == "CRITICAL" for rule_id in counts):
        risk_level = "hostile"
    elif counts:
        risk_level = "suspicious"
    else:
        risk_level = "benign"

    destinations = _browser_destination_labels(result.evidence.get("events", []))

    uncertainty = 1.0 if reduction.get("telemetry_incomplete") else (0.2 if counts else 0.0)
    outward_report = {
        "risk_level": risk_level,
        "evidence": outward_evidence,
        "capabilities_requested": ["browser.navigate"],
        "destinations": sorted(destinations),
        "canaries_tripped": [],
        "uncertainty": uncertainty,
    }
    gate = apply_scoring_matrix(outward_report, OVERRIDE_PATH, result.job_id)

    RECEIPTS_DIR.mkdir(parents=True, exist_ok=True)
    evidence_path = RECEIPTS_DIR / f"{result.job_id}.browser-evidence.json"
    _write_private_json(evidence_path, result.evidence)
    evidence_sha256 = sha256_file(evidence_path)
    request_hash = _canonical_hash(request)
    identity_hash = artifact_sha256 or request_hash
    if not isinstance(identity_hash, str) or len(identity_hash) != 64:
        raise ValueError("browser probe artifact hash must be SHA-256")
    initial_origin = origin_for_url(request["url"])
    runtime = result.runtime
    rootfs_hash = runtime.get("rootfs_sha256", "0" * 64)
    events = result.evidence.get("events", [])
    raw_streams = result.evidence.get("streams", {})
    observed_by_source = {
        source: sum(
            isinstance(event, dict) and event.get("source") == source
            for event in events
        )
        for source in ("browser", "cdp", "egress", "vm")
    }
    stream_status = {
        source: {
            "complete": raw_streams[source]["complete"],
            "event_count": raw_streams[source]["event_count"],
            "observed_event_count": observed_by_source[source],
        }
        for source in ("browser", "cdp", "egress", "vm")
    }
    browser_section = {
        "schema_version": "cindermote.browser-probe-receipt/v2",
        "input": {
            "contract_version": request["contract_version"],
            "url_sha256": hashlib.sha256(request["url"].encode("utf-8")).hexdigest(),
            "normalized_origin": initial_origin,
            "authorized_origins": request["authorized_origins"],
            "request_sha256": request_hash,
            "policy_hash": _policy_hash(policy),
            "navigation_mode": "passive",
        },
        "runtime": runtime,
        "evidence": {
            "schema_version": result.evidence.get("evidence_version"),
            "sha256": evidence_sha256,
            "stream_status": stream_status,
            "events_observed": len(events),
        },
        "artifacts": result.artifacts,
        "findings": [
            {"finding_id": rule_id, "count": counts[rule_id], "severity": severities[rule_id]}
            for rule_id in sorted(counts)
        ],
        "reduction": reduction,
    }
    detector_findings = [
        {"rule_id": rule_id, "count": counts[rule_id], "severity": severities[rule_id]}
        for rule_id in sorted(counts)
    ]
    receipt = create_receipt(
        identity={
            "job_id": result.job_id,
            "artifact_sha256": identity_hash,
            "artifact_type": "browser-probe",
            "submitted_by": submitted_by,
            "received_at": received_at,
        },
        snapshot_policy={
            "snapshot_sha256": rootfs_hash,
            "snapshot_verified_by": "host-observer (external hash + read-only drive)",
            "policy_version": policy.get("policy_version", "cindermote-hotcell-v1.3"),
            "policy_hash": _policy_hash(policy),
            "memory_snapshots": "disabled-v1",
        },
        isolation={
            "mode": "firecracker",
            "namespace_used": runtime_admitted,
            "seccomp_loaded": runtime_admitted,
            "cgroups_used": runtime_admitted,
            "mlock_used": False,
            "jailer_used": runtime_admitted,
            "kvm_used": runtime_admitted,
            "host_runtime_tmpfs": runtime.get("host_runtime_tmpfs", False),
            "host_swap_disabled": runtime.get("host_swap_disabled", False),
            "rootfs_read_only": runtime.get("rootfs_read_only", False),
            "guest_writes_tmpfs_only": runtime.get("guest_writes_tmpfs_only", False),
        },
        budgets_granted={
            **request["budgets"],
            "max_tabs": 1,
            "interaction": "passive navigation only",
            "fs_writes": "guest tmpfs only",
        },
        capabilities={
            "requested": ["browser.navigate"],
            "granted": ["browser.navigate"],
            "denied": ["browser.click", "browser.type", "browser.upload", "browser.download"],
            "binding": {"request_sha256": request_hash, "job_id": result.job_id},
        },
        telemetry_summary={
            "events_observed": len(events),
            "streams": stream_status,
            "metadata_only": True,
        },
        canaries_touched={},
        destinations_attempted=destinations,
        detector_findings=detector_findings,
        gate=gate,
        outward_report=outward_report,
        purge=result.purge,
        telemetry_incomplete=bool(reduction.get("telemetry_incomplete")) or not result.purge.get("verified_externally", False),
        budget_exhausted=any(rule_id in counts for rule_id in {"web_event_budget_exceeded", "web_redirect_budget_exceeded"}),
        residual_uncertainty=uncertainty,
        key_path=OBSERVER_KEY_PATH,
        browser_probe=browser_section,
    )
    write_receipt(RECEIPTS_DIR / f"{result.job_id}.json", receipt)
    return receipt


def _copy_into_root(source: Path, root: Path, destination: Path | None = None) -> Path:
    source = source.resolve()
    target_relative = destination or Path(str(source).lstrip("/"))
    target = root / target_relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target, follow_symlinks=True)
    return target


def _elf_links(path: Path) -> tuple[str | None, list[str]]:
    """Read PT_INTERP and DT_NEEDED without invoking an external utility."""
    try:
        data = path.read_bytes()
    except (OSError, ValueError):
        return None, []
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return None, []
    try:
        header = struct.unpack_from("<16sHHIQQQIHHHHHH", data, 0)
    except struct.error:
        return None, []
    phoff, phentsize, phnum = header[5], header[9], header[10]
    segments: list[tuple[int, int, int, int, int]] = []
    interpreter: str | None = None
    dynamic: tuple[int, int] | None = None
    for index in range(phnum):
        offset = phoff + index * phentsize
        try:
            p_type, _, p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from(
                "<IIQQQQQQ", data, offset
            )
        except struct.error:
            return interpreter, []
        segments.append((p_type, p_offset, p_vaddr, p_filesz, offset))
        if p_type == 3:  # PT_INTERP
            interpreter = data[p_offset : p_offset + p_filesz].split(b"\0", 1)[0].decode(
                "utf-8", "replace"
            )
        elif p_type == 2:  # PT_DYNAMIC
            dynamic = (p_offset, p_filesz)
    if dynamic is None:
        return interpreter, []
    needed_offsets: list[int] = []
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
        if tag == 1:
            needed_offsets.append(value)
        elif tag == 5:
            strtab_address = value
        elif tag == 10:
            strtab_size = value
    if strtab_address is None:
        return interpreter, []
    strtab_offset = None
    for p_type, p_offset, p_vaddr, p_filesz, _ in segments:
        if p_type == 1 and p_vaddr <= strtab_address < p_vaddr + p_filesz:
            strtab_offset = p_offset + (strtab_address - p_vaddr)
            break
    if strtab_offset is None:
        return interpreter, []
    names: list[str] = []
    maximum = min(len(data), strtab_offset + (strtab_size or len(data)))
    for relative in needed_offsets:
        begin = strtab_offset + relative
        if begin >= maximum:
            continue
        end = data.find(b"\0", begin, maximum)
        if end == -1:
            continue
        names.append(data[begin:end].decode("utf-8", "replace"))
    return interpreter, names


def _elf_soname(path: Path) -> str | None:
    """Read DT_SONAME from an ELF64 shared object without external tools."""
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


def _alias_soname(source: Path, copied: Path) -> None:
    """Alias a copied shared library under its SONAME beside the copy.

    The closure copies each library under its resolved file name (e.g.
    libexpat.so.1.8.7), but the dynamic loader searches by SONAME
    (libexpat.so.1).  Without the alias the chrooted interpreter dies in
    the loader before the payload runs.  The SONAME is host-supplied build
    input, but it is still bounded before it enters the guest rootfs.
    """
    soname = _elf_soname(source)
    if not soname or soname == copied.name:
        return
    if "/" in soname or soname in {".", ".."} or len(soname) > 128:
        return
    link = copied.parent / soname
    if link.exists() or link.is_symlink():
        return
    link.symlink_to(copied.name)


def _resolve_library(name: str, origin: Path) -> Path | None:
    candidates = [
        origin,
        Path("/usr/lib"),
        Path("/usr/lib64"),
        Path("/lib"),
        Path("/lib64"),
        Path("/usr/local/lib"),
    ]
    for base in (Path("/usr/lib"), Path("/lib")):
        try:
            candidates.extend(path for path in base.iterdir() if path.is_dir() and "linux" in path.name)
        except OSError:
            pass
    for directory in candidates:
        candidate = directory / name
        if candidate.exists():
            return candidate.resolve()
    return None


def _copy_binary_closure(binary: Path, root: Path, destination: Path | None = None) -> None:
    queue: list[tuple[Path, Path | None]] = [(binary.resolve(), destination)]
    seen: set[Path] = set()
    while queue:
        source, target = queue.pop()
        if source in seen:
            if target is not None and not (root / target).exists():
                copied = _copy_into_root(source, root, target)
                _alias_soname(source, copied)
            continue
        seen.add(source)
        copied = _copy_into_root(source, root, target)
        _alias_soname(source, copied)
        interpreter, libraries = _elf_links(source)
        if interpreter:
            interpreter_path = Path(interpreter)
            if interpreter_path.exists():
                queue.append((interpreter_path.resolve(), Path(interpreter.lstrip("/"))))
        for library in libraries:
            resolved = _resolve_library(library, source.parent)
            if resolved is not None:
                queue.append((resolved, Path(str(resolved).lstrip("/"))))


def _snapshot_ignore(_directory: str, names: list[str]) -> set[str]:
    excluded = {
        "site-packages",
        "dist-packages",
        "__pycache__",
        "test",
        "tests",
        "ensurepip",
        "idlelib",
        "tkinter",
        "turtledemo",
        "venv",
    }
    return {name for name in names if name in excluded or name.endswith((".pyc", ".pyo"))}


def bootstrap_snapshot() -> dict:
    """Build the minimal local rootfs tarball and its SHA-256 manifest."""
    POLICY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cindermote-snapshot-") as temporary:
        root = Path(temporary) / "rootfs"
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
        ):
            (root / relative).mkdir(parents=True, exist_ok=True)

        (root / "etc" / "passwd").write_text(
            "root:x:0:0:cindermote:/home/mote:/bin/sh\n", encoding="utf-8"
        )
        (root / "etc" / "group").write_text("root:x:0:\n", encoding="utf-8")
        (root / "etc" / "hosts").write_text(
            "127.0.0.1 localhost cindermote\n::1 localhost\n", encoding="utf-8"
        )

        python_binary = Path(sys.executable).resolve()
        _copy_binary_closure(python_binary, root, Path("usr/bin/python3"))
        stdlib = Path(sysconfig.get_path("stdlib")).resolve()
        # The payload interpreter runs as /usr/bin/python3 inside the chroot
        # and derives its stdlib location from that path (prefix /usr), not
        # from the host install layout.  Place the stdlib where the chrooted
        # interpreter computes it; fall back to mirroring the host layout
        # only when the stdlib is outside the interpreter's base prefix.
        base_prefix = Path(sys.base_prefix).resolve()
        try:
            stdlib_target = root / "usr" / stdlib.relative_to(base_prefix)
        except ValueError:
            stdlib_target = root / Path(str(stdlib).lstrip("/"))
        shutil.copytree(stdlib, stdlib_target, symlinks=False, ignore=_snapshot_ignore)
        for extension in stdlib_target.rglob("*.so"):
            original = stdlib / extension.relative_to(stdlib_target)
            if original.exists():
                _copy_binary_closure(original, root)

        for candidate in (
            Path("/usr/bin/bash"),
            Path("/bin/bash"),
            Path("/usr/bin/unshare"),
            Path("/usr/bin/env"),
            Path("/usr/bin/cat"),
            Path("/usr/bin/true"),
            Path("/usr/bin/ls"),
        ):
            if candidate.exists():
                destination = Path(str(candidate).lstrip("/"))
                _copy_binary_closure(candidate, root, destination)

        bash_target = root / "usr/bin/bash"
        if not bash_target.exists() and (root / "bin/bash").exists():
            shutil.copy2(root / "bin/bash", bash_target)
        sh_target = root / "usr/bin/sh"
        if sh_target.exists() or sh_target.is_symlink():
            sh_target.unlink()
        sh_target.symlink_to("bash")
        bin_link = root / "bin"
        if bin_link.exists() and bin_link.is_dir() and not any(bin_link.iterdir()):
            bin_link.rmdir()
        if not bin_link.exists():
            bin_link.symlink_to("usr/bin")
        elif bin_link.is_dir():
            bin_sh = bin_link / "sh"
            if bin_sh.exists() or bin_sh.is_symlink():
                bin_sh.unlink()
            bin_sh.symlink_to("bash")

        temporary_tar = SNAPSHOT_PATH.with_suffix(".tar.gz.tmp")
        with tarfile.open(temporary_tar, "w:gz", compresslevel=6) as archive:
            archive.add(root, arcname=".", recursive=True)
        os.replace(temporary_tar, SNAPSHOT_PATH)

    write_seccomp_blob(SECCOMP_BLOB_PATH)
    manifest = {
        "sha256": sha256_file(SNAPSHOT_PATH),
        "built_at": _utc_now(),
        "size_bytes": SNAPSHOT_PATH.stat().st_size,
    }
    SNAPSHOT_MANIFEST_PATH.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def verify_snapshot() -> dict:
    try:
        manifest = _json_read(SNAPSHOT_MANIFEST_PATH)
    except FileNotFoundError as exc:
        raise SnapshotIntegrityError("golden snapshot manifest is missing") from exc
    expected = manifest.get("sha256")
    if not SNAPSHOT_PATH.is_file() or not isinstance(expected, str) or len(expected) != 64:
        raise SnapshotIntegrityError("golden snapshot is unbuilt")
    actual = sha256_file(SNAPSHOT_PATH)
    if actual != expected:
        raise SnapshotIntegrityError(
            f"snapshot SHA256 mismatch: expected {expected}, observed {actual}"
        )
    return manifest


def _mount(source: str | None, target: Path | str, fs_type: str | None, flags: int, data: str | None) -> None:
    source_b = None if source is None else source.encode()
    target_b = os.fsencode(target)
    type_b = None if fs_type is None else fs_type.encode()
    data_b = None if data is None else data.encode()
    result = libc.mount(source_b, target_b, type_b, ctypes.c_ulong(flags), data_b)
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, f"mount {target}: {os.strerror(error)}")


def _drop_capabilities() -> None:
    class Header(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class Data(ctypes.Structure):
        _fields_ = [
            ("effective", ctypes.c_uint32),
            ("permitted", ctypes.c_uint32),
            ("inheritable", ctypes.c_uint32),
        ]

    header = Header(LINUX_CAPABILITY_VERSION_3, 0)
    values = (Data * 2)(Data(0, 0, 0), Data(0, 0, 0))
    if libc.capset(ctypes.byref(header), ctypes.byref(values)) != 0:
        error = ctypes.get_errno()
        raise OSError(error, f"capset: {os.strerror(error)}")


def _safe_extract(archive_path: Path, target: Path) -> None:
    with tarfile.open(archive_path, "r:gz") as archive:
        root = target.resolve()
        for member in archive.getmembers():
            destination = (target / member.name).resolve()
            if destination != root and root not in destination.parents:
                raise IsolationSetupError("snapshot contains a path traversal")
            if member.isdev() or member.isfifo():
                raise IsolationSetupError("snapshot contains a special file")
        try:
            archive.extractall(target, filter="data")
        except TypeError:
            archive.extractall(target)


def _write_control(control_fd: int, value: dict) -> None:
    payload = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )
    control = socket.socket(fileno=control_fd)
    try:
        if control.send(payload) != len(payload):
            raise OSError(errno.EIO, "short readiness control write")
    finally:
        control.detach()


def _sandbox_readiness_identity() -> dict[str, int | str]:
    """Capture the host-visible identity before chroot hides the host procfs."""

    host_pid_text = os.readlink("/proc/self")
    if not host_pid_text.isascii() or not host_pid_text.isdigit():
        raise IsolationSetupError("host-visible sandbox PID is unavailable")
    identity = _read_process_identity(int(host_pid_text))
    if identity is None:
        raise IsolationSetupError("host-visible sandbox identity is unavailable")
    return {
        "protocol": READINESS_PROTOCOL,
        "host_pid": identity.pid,
        "start_time_ticks": identity.start_time_ticks,
    }


def _seed_canaries(rootfs: Path) -> dict[str, str]:
    token = uuid.uuid4().hex
    files = {
        "canary_cred_aws": (
            Path("home/mote/.aws/credentials"),
            "aws_credentials.template",
        ),
        "canary_cred_ssh": (Path("home/mote/.ssh/id_rsa"), "ssh_id_rsa.template"),
        "canary_file": (Path("home/mote/canary_file.txt"), "canary_file.template"),
        "canary_tmp": (Path(f"tmp/canary_{token[:8]}"), "canary_file.template"),
    }
    result: dict[str, str] = {}
    for name, (relative, template_name) in files.items():
        destination = rootfs / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        template = (CANARY_TEMPLATES_DIR / template_name).read_text(encoding="utf-8")
        destination.write_text(template.format(token=token), encoding="utf-8")
        destination.chmod(0o400)
        result[name] = "/" + str(relative)
    return result


def _code_blocks(markdown: str) -> list[tuple[str, str]]:
    pattern = re.compile(r"```([^\n`]*)\n(.*?)```", re.DOTALL)
    return [(match.group(1).strip().lower(), match.group(2)) for match in pattern.finditer(markdown)]


def _prepare_artifact(rootfs: Path, source: Path, artifact_type: str) -> list[str]:
    artifact = rootfs / "artifact"
    shutil.copy2(source, artifact)
    artifact.chmod(0o444)
    if artifact_type in {"python-script", "mcp-server"}:
        return ["/usr/bin/python3", "/artifact"]
    if artifact_type == "shell-script":
        return ["/bin/bash", "/artifact"]
    if artifact_type == "skill-md":
        blocks = _code_blocks(source.read_text(encoding="utf-8", errors="replace"))
        commands: list[str] = ["#!/bin/bash", "set -eu"]
        for index, (language, body) in enumerate(blocks):
            extension = "py" if language in {"py", "python", "python3"} else "sh"
            block_path = rootfs / "tmp" / f"cindermote_block_{index}.{extension}"
            block_path.write_text(body, encoding="utf-8")
            block_path.chmod(0o500)
            interpreter = "/usr/bin/python3" if extension == "py" else "/bin/bash"
            commands.append(f"{interpreter} /tmp/{block_path.name}")
        runner = rootfs / "artifact_runner.sh"
        runner.write_text("\n".join(commands) + "\n", encoding="utf-8")
        runner.chmod(0o500)
        return ["/bin/bash", "/artifact_runner.sh"]
    if artifact_type == "tool-definition":
        runner = rootfs / "artifact_probe.py"
        runner.write_text(
            "import json\n"
            "with open('/artifact', encoding='utf-8') as f: data=json.load(f)\n"
            "tools=data.get('tools', [data]) if isinstance(data, dict) else []\n"
            "for tool in tools:\n"
            " p=tool.get('parameters', tool.get('inputSchema', {})) if isinstance(tool, dict) else {}\n"
            " props=p.get('properties', {}) if isinstance(p, dict) else {}\n"
            " trip={k:('/home/mote/canary_file.txt' if 'path' in k.lower() else 'CANARY_VALUE_12345') for k in props}\n"
            " json.dumps(trip, sort_keys=True)\n",
            encoding="utf-8",
        )
        runner.chmod(0o500)
        return ["/usr/bin/python3", "/artifact_probe.py"]
    raise ValueError(f"unsupported artifact type: {artifact_type}")


def _seal_file(path: Path) -> None:
    _mount(str(path), path, None, MS_BIND, None)
    _mount(None, path, None, MS_BIND | MS_REMOUNT | MS_RDONLY, None)


def _sandbox_child(args: argparse.Namespace) -> int:
    control_fd = int(os.environ["CINDERMOTE_CONTROL_FD"])
    job_dir = Path(args.job_dir)
    artifact = Path(args.artifact).resolve()
    snapshot = Path(args.snapshot).resolve()
    budgets = json.loads(args.budgets)
    full_root = args.isolation_mode == "full-root"
    overlay_used = False
    mlock_used = False
    device_bind_used = True
    readiness_identity: dict[str, int | str] | None = None
    stage = "capture_identity"
    try:
        readiness_identity = _sandbox_readiness_identity()
        stage = "mount_private"
        _mount(None, "/", None, MS_REC | MS_PRIVATE, None)
        stage = "mount_tmpfs"
        _mount(
            "tmpfs",
            job_dir,
            "tmpfs",
            MS_NOSUID | MS_NODEV,
            f"size={budgets['ram_mib']}m,mode=0700",
        )
        lower = job_dir / "lower"
        upper = job_dir / "upper"
        work = job_dir / "work"
        merged = job_dir / "rootfs"
        for directory in (lower, upper, work, merged):
            directory.mkdir(parents=True, exist_ok=True)
        stage = "extract_snapshot"
        _safe_extract(snapshot, lower)
        stage = "mount_overlay"
        try:
            _mount(
                "overlay",
                merged,
                "overlay",
                MS_NOSUID | MS_NODEV,
                f"lowerdir={lower},upperdir={upper},workdir={work}",
            )
            rootfs = merged
            overlay_used = True
        except OSError:
            rootfs = lower

        stage = "seed_canaries"
        canaries = _seed_canaries(rootfs)
        (rootfs / "etc/resolv.conf").write_text("nameserver 127.0.0.1\n", encoding="utf-8")
        stage = "prepare_artifact"
        command = _prepare_artifact(rootfs, artifact, args.artifact_type)
        stage = "seal_artifact"
        _seal_file(rootfs / "artifact")

        stage = "bind_devices"
        for device in ("null", "urandom"):
            target = rootfs / "dev" / device
            target.touch(exist_ok=True)
            try:
                _mount(f"/dev/{device}", target, None, MS_BIND, None)
                if device == "urandom":
                    _mount(None, target, None, MS_BIND | MS_REMOUNT | MS_RDONLY, None)
            except OSError:
                if full_root:
                    raise
                device_bind_used = False

        stage = "chroot"
        os.chroot(rootfs)
        os.chdir("/")
        os.umask(0o077)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        resource.setrlimit(resource.RLIMIT_NPROC, (budgets["pids"], budgets["pids"]))
        address_space = budgets["ram_mib"] * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (address_space, address_space))
        cpu_seconds = max(1, int(budgets["wall_clock_sec"]))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))
        resource.setrlimit(
            resource.RLIMIT_FSIZE,
            (budgets["max_output_bytes"], budgets["max_output_bytes"]),
        )
        stage = "mlock"
        if full_root:
            mlock_used = libc.mlockall(MCL_CURRENT | MCL_FUTURE) == 0
            if getattr(args, "require_mlock", False) and not mlock_used:
                raise IsolationSetupError("required mlockall failed")
        stage = "drop_capabilities"
        _drop_capabilities()
        if not full_root:
            stage = "request_tracing"
            request_tracing()
        stage = "install_seccomp"
        install_seccomp()
        stage = "signal_ready"
        _write_control(
            control_fd,
            {
                "ready": True,
                "namespace_used": True,
                "seccomp_loaded": True,
                "overlay_used": overlay_used,
                "mlock_used": mlock_used,
                "device_bind_used": device_bind_used,
                "canaries": canaries,
                "identity": readiness_identity,
            },
        )
        os.close(control_fd)
        if full_root:
            stage = "await_host_admission"
            admission_fd = int(os.environ["CINDERMOTE_ADMISSION_FD"])
            if os.read(admission_fd, len(SANDBOX_ADMISSION_TOKEN)) != SANDBOX_ADMISSION_TOKEN:
                raise IsolationSetupError("host admission token missing")
            os.close(admission_fd)
        else:
            os.kill(os.getpid(), signal.SIGSTOP)
        environment = {
            "HOME": "/home/mote",
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        os.execve(command[0], command, environment)
    except BaseException as exc:
        try:
            _write_control(
                control_fd,
                {
                    "ready": False,
                    "error": f"{type(exc).__name__}:{getattr(exc, 'errno', str(exc))}",
                    "stage": stage,
                    "namespace_used": True,
                    "seccomp_loaded": False,
                    "overlay_used": overlay_used,
                    "mlock_used": mlock_used,
                    "device_bind_used": device_bind_used,
                },
            )
        except BaseException:
            pass
        return 125


class MCPController:
    def __init__(self, stdin: Any, detector: DetectorEngine):
        self.stdin = stdin
        self.detector = detector
        self.buffer = bytearray()
        self.initialized = False
        self.tools_listed = False
        self.tools_called: list[str] = []
        self.errors: list[str] = []
        self.pending_calls: set[int] = set()
        self.done = False
        self.done_at: float | None = None

    def _send(self, payload: dict) -> None:
        try:
            self.stdin.write(json.dumps(payload, separators=(",", ":")).encode() + b"\n")
            self.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            self.errors.append(f"write:{getattr(exc, 'errno', 'closed')}")

    def start(self) -> None:
        self._send(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "cindermote-decoy", "version": "1.0.0"},
                },
            }
        )

    @staticmethod
    def _tripwire_arguments(tool: dict) -> dict:
        schema = tool.get("inputSchema", {}) if isinstance(tool, dict) else {}
        properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
        arguments: dict[str, Any] = {}
        for name, definition in properties.items():
            kind = definition.get("type", "string") if isinstance(definition, dict) else "string"
            if kind == "boolean":
                value: Any = True
            elif kind in {"number", "integer"}:
                value = 1
            elif kind == "array":
                value = []
            elif kind == "object":
                value = {}
            else:
                value = "/home/mote/canary_file.txt" if "path" in name.lower() else "CANARY_VALUE_12345"
            arguments[name] = value
        return arguments

    def feed(self, chunk: bytes) -> None:
        self.buffer.extend(chunk)
        while b"\n" in self.buffer:
            raw_line, _, remainder = self.buffer.partition(b"\n")
            self.buffer = bytearray(remainder)
            if not raw_line.strip():
                continue
            try:
                message = json.loads(raw_line)
            except (json.JSONDecodeError, UnicodeDecodeError):
                self.errors.append("malformed_jsonrpc")
                continue
            if not isinstance(message, dict):
                self.errors.append("non_object_jsonrpc")
                continue
            identifier = message.get("id")
            if "error" in message:
                self.errors.append(f"rpc_error_{identifier}")
            if identifier == 1:
                result = message.get("result", {})
                if isinstance(result, dict) and isinstance(result.get("serverInfo"), dict):
                    self.initialized = True
                    self._send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
                else:
                    self.errors.append("initialize_missing_serverInfo")
            elif identifier == 2:
                result = message.get("result", {})
                tools = result.get("tools", []) if isinstance(result, dict) else []
                if not isinstance(tools, list):
                    self.errors.append("tools_list_malformed")
                    tools = []
                self.tools_listed = True
                for index, tool in enumerate(tools, start=3):
                    if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
                        self.errors.append("tool_entry_malformed")
                        continue
                    description = tool.get("description", "")
                    if isinstance(description, str) and scan_tool_description(description):
                        self.detector.record(
                            make_event(
                                "syscall",
                                "tool_poisoning",
                                "mcp_tool_description",
                                "read",
                                "anomalous",
                            )
                        )
                    self.pending_calls.add(index)
                    self.tools_called.append(tool["name"])
                    self._send(
                        {
                            "jsonrpc": "2.0",
                            "id": index,
                            "method": "tools/call",
                            "params": {
                                "name": tool["name"],
                                "arguments": self._tripwire_arguments(tool),
                            },
                        }
                    )
                if not self.pending_calls:
                    self.done = True
                    self.done_at = time.monotonic()
            elif isinstance(identifier, int) and identifier in self.pending_calls:
                self.pending_calls.discard(identifier)
                if not self.pending_calls:
                    self.done = True
                    self.done_at = time.monotonic()

    def receipt(self) -> dict:
        return {
            "initialize_completed": self.initialized,
            "tools_list_completed": self.tools_listed,
            "tools_called": list(self.tools_called),
            "errors": list(self.errors),
        }


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for name, item in pairs:
        if name in value:
            raise ValueError("duplicate readiness control key")
        value[name] = item
    return value


def _read_control(control: socket.socket) -> ControlMessage | None:
    try:
        raw, ancillary, flags, _address = control.recvmsg(
            65536,
            socket.CMSG_SPACE(struct.calcsize("3i")),
        )
    except BlockingIOError:
        return None
    except OSError as exc:
        number = exc.errno if isinstance(exc.errno, int) else errno.EIO
        return ControlMessage(
            {"ready": False, "error": f"control_read:{number}"},
            None,
            None,
            None,
            False,
        )
    if not raw:
        return ControlMessage(
            {"ready": False, "error": "missing_control_status"},
            None,
            None,
            None,
            False,
        )
    sender: tuple[int, int, int] | None = None
    credentials_valid = not bool(flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC))
    for level, message_type, data in ancillary:
        if level != socket.SOL_SOCKET or message_type != socket.SCM_CREDENTIALS:
            continue
        if sender is not None or len(data) < struct.calcsize("3i"):
            credentials_valid = False
            continue
        sender = struct.unpack("3i", data[: struct.calcsize("3i")])
    credentials_valid = bool(credentials_valid and sender is not None)
    payload = raw[:-1] if raw.endswith(b"\n") else raw
    try:
        value = json.loads(payload, object_pairs_hook=_reject_duplicate_json_keys)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        value = {"ready": False, "error": "malformed_control_status"}
    if not isinstance(value, dict):
        value = {"ready": False, "error": "invalid_control_status"}
    return ControlMessage(
        value,
        sender[0] if sender is not None else None,
        sender[1] if sender is not None else None,
        sender[2] if sender is not None else None,
        credentials_valid,
    )


def _write_alert(job_id: str, reason: str, details: dict | None = None) -> None:
    ALERTS_DIR.mkdir(parents=True, exist_ok=True)
    payload = {"job_id": job_id, "reason": reason, "at": _utc_now(), "details": details or {}}
    path = ALERTS_DIR / f"{job_id}.alert"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _mark_host_state(path: Path, job_id: str, reason: str) -> None:
    record = json.dumps(
        {"job_id": job_id, "reason": reason, "at": _utc_now()},
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(descriptor, record.encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _capture_process_evidence(job_id: str, pids: set[int]) -> None:
    """Preserve bounded host-side process evidence before a SEV-1 kill."""
    ALERTS_DIR.mkdir(parents=True, exist_ok=True)
    evidence: dict[str, dict] = {}
    for pid in sorted(pids):
        item: dict[str, Any] = {"maps": None, "fds": {}}
        try:
            item["maps"] = Path(f"/proc/{pid}/maps").read_text(
                encoding="utf-8", errors="replace"
            )[:131072]
        except (OSError, PermissionError):
            pass
        fd_root = Path(f"/proc/{pid}/fd")
        try:
            for descriptor in list(fd_root.iterdir())[:128]:
                try:
                    item["fds"][descriptor.name] = os.readlink(descriptor)
                except OSError:
                    item["fds"][descriptor.name] = "unreadable"
        except (OSError, PermissionError):
            pass
        evidence[str(pid)] = item
    destination = ALERTS_DIR / f"{job_id}.proc.json"
    destination.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    destination.chmod(0o600)


def _preflight_artifact(path: Path, artifact_type: str, detector: DetectorEngine) -> None:
    if artifact_type == "tool-definition":
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            detector.record(
                make_event(
                    "syscall", "malformed_report", "tool_definition", "read", "known_bad"
                )
            )
            return
        tools = value.get("tools", [value]) if isinstance(value, dict) else []
        for tool in tools if isinstance(tools, list) else []:
            if isinstance(tool, dict) and isinstance(tool.get("description"), str):
                if scan_tool_description(tool["description"]):
                    detector.record(
                        make_event(
                            "syscall",
                            "tool_poisoning",
                            "tool_definition_description",
                            "read",
                            "anomalous",
                        )
                    )


def _setup_cgroup(job_id: str, budgets: dict) -> Path | None:
    if os.geteuid() != 0:
        return None
    root = LEGACY_CGROUP_ROOT
    group = root / job_id
    stage = "create_root"
    try:
        root.mkdir(exist_ok=True)
        stage = "create_job"
        group.mkdir()
        stage = "write_cpu_max"
        (group / "cpu.max").write_text(
            f"{100000 * budgets['cpu_vcpu']} 100000\n", encoding="ascii"
        )
        stage = "write_memory_max"
        (group / "memory.max").write_text(
            f"{budgets['ram_mib'] * 1024 * 1024}\n", encoding="ascii"
        )
        stage = "write_memory_swap_max"
        (group / "memory.swap.max").write_text("0\n", encoding="ascii")
        stage = "write_pids_max"
        (group / "pids.max").write_text(f"{budgets['pids']}\n", encoding="ascii")
        return group
    except OSError as exc:
        try:
            group.rmdir()
        except OSError:
            pass
        raise CgroupOperationError(stage, exc) from exc


def _process_group_members(process_group: int) -> tuple[list[int], bool]:
    try:
        entries = list(Path("/proc").iterdir())
    except OSError:
        return [], False
    members: list[int] = []
    complete = True
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            stat_fields = (entry / "stat").read_text(encoding="ascii").rpartition(")")[2].split()
            if len(stat_fields) >= 3 and int(stat_fields[2]) == process_group:
                members.append(int(entry.name))
        except (FileNotFoundError, ProcessLookupError):
            continue
        except (PermissionError, ValueError, OSError):
            complete = False
    return sorted(members), complete


def _cgroup_members(group: Path | None) -> tuple[list[int], bool]:
    if group is None or not group.exists():
        return [], True
    try:
        members = [int(value) for value in (group / "cgroup.procs").read_text(encoding="ascii").split()]
    except FileNotFoundError:
        return ([], True) if not group.exists() else ([], False)
    except (OSError, ValueError):
        return [], False
    return sorted(set(members)), True


def _join_cgroup(group: Path, pid: int) -> None:
    try:
        (group / "cgroup.procs").write_text(f"{pid}\n", encoding="ascii")
    except OSError as exc:
        raise CgroupOperationError("join_wrapper", exc) from exc
    members, known = _cgroup_members(group)
    if not known or pid not in members:
        raise CgroupOperationError("verify_wrapper_membership", errno.ESRCH)


def _read_process_identity(pid: int) -> ProcessIdentity | None:
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return None
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
        return None
    _head, separator, tail = raw.rpartition(")")
    fields = tail.split() if separator else []
    if len(fields) < 20:
        return None
    try:
        return ProcessIdentity(
            pid=pid,
            state=fields[0],
            parent_pid=int(fields[1]),
            process_group=int(fields[2]),
            session=int(fields[3]),
            start_time_ticks=int(fields[19]),
        )
    except (IndexError, ValueError):
        return None


def _validate_wrapper_identity(
    expected: ProcessIdentity,
) -> ProcessIdentity:
    current = _read_process_identity(expected.pid)
    if current is None:
        raise SandboxIdentityError("wrapper_process_missing")
    if current.start_time_ticks != expected.start_time_ticks:
        raise SandboxIdentityError("wrapper_identity_changed")
    if current.state in {"X", "Z"}:
        raise SandboxIdentityError("wrapper_exited")
    if current.process_group != expected.pid:
        raise SandboxIdentityError("wrapper_process_group_mismatch")
    if current.session != expected.pid:
        raise SandboxIdentityError("wrapper_session_mismatch")
    return current


def _validate_sandbox_process(
    pid: int,
    start_time_ticks: int,
    wrapper: ProcessIdentity,
    cgroup: Path | None,
    *,
    full_root: bool,
    require_stopped: bool,
) -> ProcessIdentity:
    _validate_wrapper_identity(wrapper)
    child = _read_process_identity(pid)
    if child is None:
        raise SandboxIdentityError("sandbox_process_missing")
    if child.start_time_ticks != start_time_ticks:
        raise SandboxIdentityError("readiness_start_time_mismatch")
    if full_root:
        if child.pid == wrapper.pid or child.parent_pid != wrapper.pid:
            raise SandboxIdentityError("sandbox_ancestry_mismatch")
    elif child.pid != wrapper.pid:
        raise SandboxIdentityError("sandbox_ancestry_mismatch")
    if child.process_group != wrapper.pid:
        raise SandboxIdentityError("sandbox_process_group_mismatch")
    if child.session != wrapper.pid:
        raise SandboxIdentityError("sandbox_session_mismatch")
    if full_root:
        members, known = _cgroup_members(cgroup)
        if not known or wrapper.pid not in members or child.pid not in members:
            raise SandboxIdentityError("sandbox_cgroup_mismatch")
    if child.state in {"X", "Z"}:
        raise SandboxIdentityError("sandbox_process_missing")
    if require_stopped and child.state not in {"T", "t"}:
        raise SandboxIdentityError("sandbox_not_stopped")
    return child


def _inspect_sandbox_identity(
    message: ControlMessage | None,
    wrapper: ProcessIdentity,
    cgroup: Path | None,
    *,
    full_root: bool,
    require_stopped: bool,
) -> SandboxAdmission:
    if message is None:
        raise SandboxIdentityError("readiness_absent")
    if message.status.get("ready") is not True:
        raise SandboxIdentityError("readiness_not_ready")
    if not message.credentials_valid or message.sender_pid is None:
        raise SandboxIdentityError("readiness_credentials_missing")
    if any(
        not isinstance(message.status.get(name), bool)
        for name in (
            "namespace_used",
            "seccomp_loaded",
            "overlay_used",
            "mlock_used",
            "device_bind_used",
        )
    ):
        raise SandboxIdentityError("readiness_status_malformed")
    canaries = message.status.get("canaries")
    if (
        not isinstance(canaries, dict)
        or len(canaries) > 16
        or any(
            not isinstance(name, str)
            or not name
            or len(name) > 64
            or not isinstance(path, str)
            or not path.startswith("/")
            or len(path) > 512
            for name, path in canaries.items()
        )
    ):
        raise SandboxIdentityError("readiness_status_malformed")
    claimed = message.status.get("identity")
    if not isinstance(claimed, dict) or set(claimed) != {
        "protocol",
        "host_pid",
        "start_time_ticks",
    }:
        raise SandboxIdentityError("readiness_identity_malformed")
    claimed_pid = claimed.get("host_pid")
    claimed_start = claimed.get("start_time_ticks")
    if (
        claimed.get("protocol") != READINESS_PROTOCOL
        or isinstance(claimed_pid, bool)
        or not isinstance(claimed_pid, int)
        or claimed_pid <= 0
        or isinstance(claimed_start, bool)
        or not isinstance(claimed_start, int)
        or claimed_start < 0
    ):
        raise SandboxIdentityError("readiness_identity_malformed")
    if claimed_pid != message.sender_pid:
        raise SandboxIdentityError("readiness_pid_mismatch")
    _validate_sandbox_process(
        claimed_pid,
        claimed_start,
        wrapper,
        cgroup,
        full_root=full_root,
        require_stopped=require_stopped,
    )
    try:
        pidfd = os.pidfd_open(claimed_pid, 0)
    except (AttributeError, OSError) as exc:
        raise SandboxIdentityError("sandbox_pidfd_open") from exc
    admission = SandboxAdmission(claimed_pid, claimed_start, pidfd)
    try:
        _validate_sandbox_process(
            admission.pid,
            admission.start_time_ticks,
            wrapper,
            cgroup,
            full_root=full_root,
            require_stopped=require_stopped,
        )
    except BaseException:
        admission.close()
        raise
    return admission


def _stop_sandbox_at_barrier(
    admission: SandboxAdmission,
    wrapper: ProcessIdentity,
    cgroup: Path,
    deadline: float,
) -> None:
    try:
        signal.pidfd_send_signal(admission.pidfd, signal.SIGSTOP)
    except (AttributeError, OSError) as exc:
        raise SandboxIdentityError("sandbox_pidfd_stop") from exc
    while time.monotonic() < deadline:
        try:
            _validate_sandbox_process(
                admission.pid,
                admission.start_time_ticks,
                wrapper,
                cgroup,
                full_root=True,
                require_stopped=True,
            )
            return
        except SandboxIdentityError as exc:
            if exc.stage != "sandbox_not_stopped":
                raise
        time.sleep(0.005)
    raise SandboxIdentityError("sandbox_not_stopped")


def _validate_tracer_target(tracer: HostTracer, admission: SandboxAdmission | None) -> None:
    if admission is None or tracer.root_pid != admission.pid:
        raise SandboxIdentityError("tracer_pid_mismatch")


def _control_status_evidence(message: ControlMessage | None) -> dict[str, Any]:
    if message is None:
        return {"ready": False, "error": "readiness_absent"}
    evidence: dict[str, Any] = {}
    for name in (
        "ready",
        "namespace_used",
        "seccomp_loaded",
        "overlay_used",
        "mlock_used",
        "device_bind_used",
    ):
        if isinstance(message.status.get(name), bool):
            evidence[name] = message.status[name]
    for name in ("error", "stage"):
        value = message.status.get(name)
        if isinstance(value, str):
            evidence[name] = value[:128]
    return evidence


def _mountinfo_unescape(value: str) -> str:
    return re.sub(
        r"\\([0-7]{3})",
        lambda match: chr(int(match.group(1), 8)),
        value,
    )


def _job_mounts(job_dir: Path) -> tuple[list[Path], bool]:
    try:
        lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except OSError:
        return [], False
    mounts: list[Path] = []
    for line in lines:
        fields = line.split(" - ", 1)[0].split()
        if len(fields) < 5:
            return [], False
        mountpoint = Path(_mountinfo_unescape(fields[4]))
        if mountpoint == job_dir or job_dir in mountpoint.parents:
            mounts.append(mountpoint)
    return sorted(set(mounts), key=lambda path: len(path.parts), reverse=True), True


def _reap_process_group(process_group: int | None) -> None:
    if process_group is None or process_group <= 0:
        return
    while True:
        try:
            waited_pid, _status = os.waitpid(-process_group, os.WNOHANG | WAIT_WALL)
        except (ChildProcessError, ProcessLookupError, OSError):
            return
        if waited_pid <= 0:
            return


def _cleanup_legacy_resources(
    process_group: int | None,
    cgroup: Path | None,
    job_dir: Path,
    *,
    tracked_pids: set[int] | None = None,
) -> dict[str, Any]:
    """Terminate and externally verify every host-owned legacy job resource."""

    tracked = set(tracked_pids or ())
    if process_group is not None and process_group > 0:
        try:
            os.killpg(process_group, signal.SIGKILL)
        except OSError:
            pass
    for pid in tracked:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass

    if cgroup is not None and cgroup.exists():
        try:
            kill_file = cgroup / "cgroup.kill"
            if kill_file.exists():
                kill_file.write_text("1\n", encoding="ascii")
        except OSError:
            pass

    deadline = time.monotonic() + 2.0
    group_members: list[int] = []
    group_known = True
    cgroup_pids: list[int] = []
    cgroup_known = True
    tracked_remaining: list[int] = []
    while True:
        _reap_process_group(process_group)
        if process_group is None or process_group <= 0:
            group_members, group_known = [], True
        else:
            group_members, group_known = _process_group_members(process_group)
        cgroup_pids, cgroup_known = _cgroup_members(cgroup)
        tracked_remaining = [pid for pid in sorted(tracked) if Path(f"/proc/{pid}").exists()]
        if group_known and not group_members and cgroup_known and not cgroup_pids and not tracked_remaining:
            break
        if time.monotonic() >= deadline:
            break
        for pid in set(group_members) | set(cgroup_pids) | set(tracked_remaining):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        time.sleep(0.01)

    cgroup_empty = cgroup_known and not cgroup_pids
    if cgroup is not None and cgroup.exists() and cgroup_empty:
        try:
            cgroup.rmdir()
        except OSError:
            pass
    cgroup_removed = cgroup is None or not cgroup.exists()

    mounts, mounts_known = _job_mounts(job_dir)
    if mounts_known:
        for mountpoint in mounts:
            try:
                libc.umount2(os.fsencode(mountpoint), 0)
            except AttributeError:
                break
        mounts, mounts_known = _job_mounts(job_dir)
    job_mount_removed = mounts_known and not mounts
    if job_mount_removed:
        try:
            shutil.rmtree(job_dir)
        except FileNotFoundError:
            pass
        except OSError:
            pass
    job_directory_removed = not job_dir.exists()

    remaining: list[str] = []
    if not group_known:
        remaining.append("process_table:unreadable")
    remaining.extend(f"process_group:{process_group}:{pid}" for pid in group_members)
    remaining.extend(f"tracked_process:{pid}" for pid in tracked_remaining)
    if not cgroup_known and cgroup is not None:
        remaining.append(f"cgroup_membership:unreadable:{cgroup}")
    remaining.extend(f"cgroup_process:{pid}" for pid in cgroup_pids)
    if not cgroup_removed and cgroup is not None:
        remaining.append(f"cgroup:{cgroup}")
    if not mounts_known:
        remaining.append("mount_table:unreadable")
    remaining.extend(f"mount:{mountpoint}" for mountpoint in mounts)
    if not job_directory_removed:
        remaining.append(f"job_directory:{job_dir}")
    remaining = sorted(set(remaining))
    process_ids = set(group_members) | set(cgroup_pids) | set(tracked_remaining)
    process_group_empty = group_known and not group_members
    verified = bool(
        process_group_empty
        and cgroup_empty
        and cgroup_removed
        and job_mount_removed
        and job_directory_removed
        and not process_ids
        and not remaining
    )
    return {
        "method": "SIGKILL + process-group/cgroup drain + mount/job-directory removal",
        "verified_externally": verified,
        "process_group_empty": process_group_empty,
        "cgroup_empty": cgroup_empty,
        "cgroup_removed": cgroup_removed,
        "job_mount_removed": job_mount_removed,
        "job_directory_removed": job_directory_removed,
        "processes_remaining": len(process_ids),
        "remaining_host_resources": remaining,
    }


def _isolation_admission_failures(
    setup_ready: bool,
    controls: dict[str, bool],
    required_controls: dict[str, bool],
) -> list[str]:
    failures = [] if setup_ready else ["sandbox_ready"]
    failures.extend(
        name
        for name, required in required_controls.items()
        if required and not controls.get(name, False)
    )
    return sorted(set(failures))


def _record_isolation_admission_failure(detector: DetectorEngine) -> None:
    detector.record(
        make_event(
            "syscall",
            "isolation_admission_failure",
            "required_isolation_control_missing",
            "exit",
            "known_bad",
        )
    )


_OBSERVATION_LOAD_SIGNATURES = (
    b"error while loading shared libraries",
    b"cannot open shared object file",
    b"Fatal Python error: init_",
    b"ModuleNotFoundError: No module named 'encodings'",
)
_WRAPPER_WARNING_PREFIX = b"WARNING: Cindermote is using degraded-user isolation"


def _bounded_diagnostic_line(line: bytes, limit: int = 240) -> str:
    text = line.decode("ascii", errors="replace")
    printable = "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in text)
    return printable[:limit]


def _observation_load_diagnostic(raw_stderr: bytes) -> tuple[str, str]:
    """Reduce bounded sandbox stderr to (failure_class, diagnostic excerpt).

    failure_class is "library_load" when a loader or interpreter-init failure
    signature is present, else "".  stderr is already bounded by the output
    budget; on the paths that consume this, the payload never executed, so the
    bytes come from the trusted wrapper, loader, or interpreter — not the
    artifact.
    """
    fallback = ""
    for line in raw_stderr.split(b"\n"):
        stripped = line.strip()
        if not stripped or stripped.startswith(_WRAPPER_WARNING_PREFIX):
            continue
        if not fallback:
            fallback = _bounded_diagnostic_line(stripped)
        if any(signature in stripped for signature in _OBSERVATION_LOAD_SIGNATURES):
            return "library_load", _bounded_diagnostic_line(stripped)
    return "", fallback


def _empty_legacy_telemetry_summary() -> dict[str, int | str]:
    return {
        "syscall_events": 0,
        "fs_mutations": 0,
        "dns_attempts": 0,
        "exec_spawns": 0,
        "source": "ptrace + seccomp (read-only, host side)",
    }


def _deny_before_sandbox_launch(
    *,
    artifact: Path,
    artifact_type: str,
    submitted_by: str,
    policy: dict,
    budgets: dict,
    job_id: str,
    received_at: str,
    manifest: dict,
    detector: DetectorEngine,
    broker: CapabilityBroker,
    isolation_mode: str,
    job_dir: Path,
    cleanup_cgroup: Path | None,
    process_group: int | None,
    tracked_pids: set[int] | None,
    diagnostic: dict[str, Any],
) -> dict:
    """Emit a signed fail-closed receipt without executing a sandbox child."""

    controls = {
        "namespace_used": False,
        "seccomp_loaded": False,
        "cgroups_used": False,
        "mlock_used": False,
    }
    failures = _isolation_admission_failures(
        False,
        controls,
        required_isolation_controls(isolation_mode, policy),
    )
    _record_isolation_admission_failure(detector)
    detector.mark_telemetry_loss()
    purge = _cleanup_legacy_resources(
        process_group,
        cleanup_cgroup,
        job_dir,
        tracked_pids=tracked_pids,
    )
    alert_details: dict[str, Any] = {
        "failed_requirements": failures,
        "diagnostic": diagnostic,
    }
    if not purge["verified_externally"]:
        detector.record(
            make_event(
                "syscall",
                "purge_failure",
                "legacy_cleanup_postcondition_failed",
                "exit",
                "known_bad",
            )
        )
        alert_details["purge"] = {
            "processes_remaining": purge["processes_remaining"],
            "remaining_host_resources": purge["remaining_host_resources"],
        }
        _mark_host_state(
            PROJECT_DIR / ".decommissioned_hosts",
            job_id,
            "purge_uncertainty",
        )
    _write_alert(job_id, "isolation_setup_failure", alert_details)
    outward_report = broker.build_report(uncertainty=1.0)
    gate = apply_scoring_matrix(outward_report, OVERRIDE_PATH, job_id)
    receipt = create_receipt(
        identity={
            "job_id": job_id,
            "artifact_sha256": sha256_file(artifact),
            "artifact_type": artifact_type,
            "submitted_by": submitted_by,
            "received_at": received_at,
        },
        snapshot_policy={
            "snapshot_sha256": manifest["sha256"],
            "snapshot_verified_by": "host-observer (external)",
            "policy_version": policy.get("policy_version", "cindermote-hotcell-v1.1"),
            "policy_hash": _policy_hash(policy),
        },
        isolation={"mode": isolation_mode, **controls},
        budgets_granted={
            "wall_clock_sec": budgets["wall_clock_sec"],
            "cpu_vcpu": budgets["cpu_vcpu"],
            "ram_mib": budgets["ram_mib"],
            "syscalls": "capped",
            "fs_writes": "RAM overlay only",
        },
        capabilities={
            "requested": broker.requested,
            "granted": broker.granted,
            "denied": broker.denied,
        },
        telemetry_summary=_empty_legacy_telemetry_summary(),
        canaries_touched={},
        destinations_attempted={},
        detector_findings=detector.findings(),
        gate=gate,
        outward_report=outward_report,
        purge=purge,
        telemetry_incomplete=True,
        budget_exhausted=False,
        residual_uncertainty=1.0,
        key_path=OBSERVER_KEY_PATH,
        active_policy=policy,
    )
    RECEIPTS_DIR.mkdir(parents=True, exist_ok=True)
    write_receipt(
        RECEIPTS_DIR / f"{job_id}.json",
        receipt,
        active_policy=policy,
    )
    return receipt


def detonate(
    artifact_path: str | Path,
    artifact_type: str,
    policy_json: str | Path | dict | None = None,
    *,
    submitted_by: str = "local-cli",
) -> dict:
    """Execute one sealed detonation and return its signed receipt."""
    artifact = Path(artifact_path).resolve()
    if artifact_type not in VALID_ARTIFACT_TYPES:
        raise ValueError(f"invalid artifact type: {artifact_type}")
    if not artifact.is_file():
        raise FileNotFoundError(artifact)
    if artifact_type == "browser-probe":
        request = _json_read(artifact)
        return detonate_browser_probe(
            request,
            policy_json,
            submitted_by=submitted_by,
            artifact_sha256=sha256_file(artifact),
        )
    policy = load_policy(policy_json)
    budgets = policy["budgets"]
    job_id = "mf-run-" + uuid.uuid4().hex[:8]
    received_at = _utc_now()
    try:
        manifest = verify_snapshot()
    except SnapshotIntegrityError as exc:
        _write_alert(job_id, "snapshot_integrity_failure", {"error": str(exc)})
        raise

    detector = DetectorEngine(max_events=budgets.get("max_telemetry_events", 10_000))
    _preflight_artifact(artifact, artifact_type, detector)
    broker = CapabilityBroker(detector)
    broker.request_capabilities([])

    isolation_mode = "full-root" if os.geteuid() == 0 else "degraded-user"
    required_controls = required_isolation_controls(isolation_mode, policy)
    if isolation_mode == "degraded-user":
        print(
            "WARNING: degraded-user isolation: cgroups and mlock are unavailable; "
            "user/mount/network/IPC/UTS namespaces, chroot, rlimits, ptrace, and seccomp remain active.",
            file=sys.stderr,
        )
    job_dir = Path("/tmp/cindermote") / job_id
    job_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
    cgroup: Path | None = None
    if isolation_mode == "full-root":
        try:
            cgroup = _setup_cgroup(job_id, budgets)
            if cgroup is None:
                raise CgroupOperationError("create_job", errno.ENODEV)
        except CgroupOperationError as exc:
            return _deny_before_sandbox_launch(
                artifact=artifact,
                artifact_type=artifact_type,
                submitted_by=submitted_by,
                policy=policy,
                budgets=budgets,
                job_id=job_id,
                received_at=received_at,
                manifest=manifest,
                detector=detector,
                broker=broker,
                isolation_mode=isolation_mode,
                job_dir=job_dir,
                cleanup_cgroup=LEGACY_CGROUP_ROOT / job_id,
                process_group=None,
                tracked_pids=None,
                diagnostic={"cgroup": exc.evidence()},
            )

    control_host: socket.socket | None = None
    control_child: socket.socket | None = None
    launch_gate_read: int | None = None
    launch_gate_write: int | None = None
    admission_read: int | None = None
    admission_write: int | None = None
    try:
        control_host, control_child = socket.socketpair(
            socket.AF_UNIX,
            socket.SOCK_SEQPACKET,
        )
        control_host.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        control_host.setblocking(False)
        if isolation_mode == "full-root":
            launch_gate_read, launch_gate_write = os.pipe()
            admission_read, admission_write = os.pipe()
    except OSError as exc:
        for control in (control_host, control_child):
            if control is not None:
                control.close()
        for descriptor in (
            launch_gate_read,
            launch_gate_write,
            admission_read,
            admission_write,
        ):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        return _deny_before_sandbox_launch(
            artifact=artifact,
            artifact_type=artifact_type,
            submitted_by=submitted_by,
            policy=policy,
            budgets=budgets,
            job_id=job_id,
            received_at=received_at,
            manifest=manifest,
            detector=detector,
            broker=broker,
            isolation_mode=isolation_mode,
            job_dir=job_dir,
            cleanup_cgroup=cgroup,
            process_group=None,
            tracked_pids=None,
            diagnostic={
                "launch": {
                    "stage": "prepare_launch_channels",
                    "errno": exc.errno if isinstance(exc.errno, int) else errno.EIO,
                }
            },
        )
    if control_host is None or control_child is None:
        return _deny_before_sandbox_launch(
            artifact=artifact,
            artifact_type=artifact_type,
            submitted_by=submitted_by,
            policy=policy,
            budgets=budgets,
            job_id=job_id,
            received_at=received_at,
            manifest=manifest,
            detector=detector,
            broker=broker,
            isolation_mode=isolation_mode,
            job_dir=job_dir,
            cleanup_cgroup=cgroup,
            process_group=None,
            tracked_pids=None,
            diagnostic={
                "launch": {"stage": "prepare_launch_channels", "errno": errno.EIO}
            },
        )
    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "CINDERMOTE_CONTROL_FD": str(control_child.fileno()),
    }
    if launch_gate_read is not None and admission_read is not None:
        environment["CINDERMOTE_LAUNCH_GATE_FD"] = str(launch_gate_read)
        environment["CINDERMOTE_ADMISSION_FD"] = str(admission_read)
    namespace_script = PROJECT_DIR / "mote" / "namespace_setup.sh"
    command = [
        str(namespace_script),
        sys.executable,
        str(THIS_FILE),
        "--sandbox-child",
        "--job-dir",
        str(job_dir),
        "--artifact",
        str(artifact),
        "--artifact-type",
        artifact_type,
        "--snapshot",
        str(SNAPSHOT_PATH),
        "--budgets",
        json.dumps(budgets, separators=(",", ":")),
        "--isolation-mode",
        isolation_mode,
    ]
    if required_controls["mlock_used"]:
        command.append("--require-mlock")
    inherited_fds = [control_child.fileno()]
    inherited_fds.extend(
        descriptor
        for descriptor in (launch_gate_read, admission_read)
        if descriptor is not None
    )
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=tuple(inherited_fds),
            env=environment,
            start_new_session=True,
            bufsize=0,
        )
    except OSError as exc:
        control_host.close()
        control_child.close()
        for descriptor in (
            launch_gate_read,
            launch_gate_write,
            admission_read,
            admission_write,
        ):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        return _deny_before_sandbox_launch(
            artifact=artifact,
            artifact_type=artifact_type,
            submitted_by=submitted_by,
            policy=policy,
            budgets=budgets,
            job_id=job_id,
            received_at=received_at,
            manifest=manifest,
            detector=detector,
            broker=broker,
            isolation_mode=isolation_mode,
            job_dir=job_dir,
            cleanup_cgroup=cgroup,
            process_group=None,
            tracked_pids=None,
            diagnostic={
                "launch": {
                    "stage": "launch_wrapper",
                    "errno": exc.errno if isinstance(exc.errno, int) else errno.EIO,
                }
            },
        )

    control_child.close()
    for descriptor in (launch_gate_read, admission_read):
        if descriptor is not None:
            os.close(descriptor)

    wrapper_identity = _read_process_identity(process.pid)
    launch_error: CgroupOperationError | SandboxIdentityError | None = None
    if wrapper_identity is None:
        launch_error = SandboxIdentityError("wrapper_process_missing")
    elif isolation_mode == "full-root":
        try:
            if cgroup is None:
                raise CgroupOperationError("verify_wrapper_membership", errno.ENOENT)
            _join_cgroup(cgroup, process.pid)
            _validate_wrapper_identity(wrapper_identity)
            if launch_gate_write is None:
                raise CgroupOperationError("release_wrapper", errno.EBADF)
            if os.write(launch_gate_write, CGROUP_LAUNCH_TOKEN) != len(
                CGROUP_LAUNCH_TOKEN
            ):
                raise CgroupOperationError("release_wrapper", errno.EIO)
        except CgroupOperationError as exc:
            launch_error = exc
        except SandboxIdentityError as exc:
            launch_error = exc
        except OSError as exc:
            launch_error = CgroupOperationError("release_wrapper", exc)
        finally:
            if launch_gate_write is not None:
                try:
                    os.close(launch_gate_write)
                except OSError:
                    pass
                launch_gate_write = None
    else:
        try:
            _validate_wrapper_identity(wrapper_identity)
        except SandboxIdentityError as exc:
            launch_error = exc

    if launch_error is not None:
        control_host.close()
        if admission_write is not None:
            os.close(admission_write)
            admission_write = None
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()
        diagnostic = (
            {"cgroup": launch_error.evidence()}
            if isinstance(launch_error, CgroupOperationError)
            else {"readiness": {"stage": launch_error.stage}}
        )
        receipt = _deny_before_sandbox_launch(
            artifact=artifact,
            artifact_type=artifact_type,
            submitted_by=submitted_by,
            policy=policy,
            budgets=budgets,
            job_id=job_id,
            received_at=received_at,
            manifest=manifest,
            detector=detector,
            broker=broker,
            isolation_mode=isolation_mode,
            job_dir=job_dir,
            cleanup_cgroup=cgroup,
            process_group=process.pid,
            tracked_pids={process.pid},
            diagnostic=diagnostic,
        )
        try:
            process.poll()
        except (ChildProcessError, OSError):
            pass
        return receipt

    control_message: ControlMessage | None = None
    admission: SandboxAdmission | None = None
    admission_error: SandboxIdentityError | None = None
    initial_status: int | None = None
    setup_deadline = time.monotonic() + min(10.0, budgets["wall_clock_sec"])
    if isolation_mode == "full-root":
        while time.monotonic() < setup_deadline:
            control_message = control_message or _read_control(control_host)
            if control_message is not None:
                try:
                    admission = _inspect_sandbox_identity(
                        control_message,
                        wrapper_identity,
                        cgroup,
                        full_root=True,
                        require_stopped=False,
                    )
                    if cgroup is None:
                        raise SandboxIdentityError("sandbox_cgroup_mismatch")
                    _stop_sandbox_at_barrier(
                        admission,
                        wrapper_identity,
                        cgroup,
                        setup_deadline,
                    )
                except SandboxIdentityError as exc:
                    admission_error = exc
                    if admission is not None:
                        admission.close()
                        admission = None
                break
            try:
                _validate_wrapper_identity(wrapper_identity)
            except SandboxIdentityError as exc:
                admission_error = exc
                break
            time.sleep(0.005)
    else:
        while time.monotonic() < setup_deadline:
            control_message = control_message or _read_control(control_host)
            try:
                waited_pid, status = os.waitpid(
                    process.pid,
                    os.WNOHANG | os.WUNTRACED,
                )
            except ChildProcessError:
                admission_error = SandboxIdentityError("wrapper_exited")
                break
            if waited_pid:
                initial_status = status
            if control_message is not None and initial_status is not None:
                break
            time.sleep(0.005)
        if (
            control_message is not None
            and initial_status is not None
            and os.WIFSTOPPED(initial_status)
        ):
            try:
                admission = _inspect_sandbox_identity(
                    control_message,
                    wrapper_identity,
                    None,
                    full_root=False,
                    require_stopped=True,
                )
            except SandboxIdentityError as exc:
                admission_error = exc
        elif admission_error is None:
            admission_error = SandboxIdentityError(
                "readiness_absent" if control_message is None else "sandbox_not_stopped"
            )

    if admission is None and admission_error is None:
        admission_error = SandboxIdentityError(
            "readiness_absent" if control_message is None else "sandbox_not_stopped"
        )
    control_host.close()
    setup_status = control_message.status if control_message is not None else None
    namespace_used = bool(setup_status and setup_status.get("namespace_used"))
    seccomp_loaded = bool(setup_status and setup_status.get("seccomp_loaded"))
    mlock_used = bool(setup_status and setup_status.get("mlock_used"))
    isolation_controls = {
        "namespace_used": namespace_used,
        "seccomp_loaded": seccomp_loaded,
        "cgroups_used": bool(isolation_mode == "full-root" and admission is not None),
        "mlock_used": mlock_used,
    }
    setup_ready = bool(admission is not None and setup_status and setup_status.get("ready") is True)
    isolation_failures = _isolation_admission_failures(
        setup_ready,
        isolation_controls,
        required_controls,
    )
    canary_paths = (setup_status or {}).get("canaries", {})
    tracer = HostTracer(
        admission.pid if admission is not None else process.pid,
        detector,
        exec_depth_limit=policy.get("detectors", {}).get("exec_spawn_depth", 3),
        timing_limit=policy.get("detectors", {}).get("timing_evasion_per_second", 100),
    )
    if not isolation_failures:
        try:
            _validate_tracer_target(tracer, admission)
        except SandboxIdentityError as exc:
            admission_error = exc
            setup_ready = False
            isolation_failures = _isolation_admission_failures(
                setup_ready,
                isolation_controls,
                required_controls,
            )
    if isolation_failures:
        _record_isolation_admission_failure(detector)
    telemetry_incomplete = False
    budget_exhausted = False
    output_truncated = False
    raw_stdout = bytearray()
    raw_stderr = bytearray()
    mcp = MCPController(process.stdin, detector) if artifact_type == "mcp-server" else None
    selector = selectors.DefaultSelector()
    for stream, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
        if stream is not None:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)

    cleanup_pids: set[int] = {process.pid}
    if admission is not None:
        cleanup_pids.add(admission.pid)
    if isolation_failures:
        telemetry_incomplete = True
        detector.mark_telemetry_loss()
        if admission_write is not None:
            try:
                os.close(admission_write)
            except OSError:
                pass
            admission_write = None
        _write_alert(
            job_id,
            "isolation_setup_failure",
            {
                "status": _control_status_evidence(control_message),
                "readiness": {
                    "stage": (
                        admission_error.stage
                        if admission_error is not None
                        else "readiness_not_ready"
                    )
                },
                "failed_requirements": isolation_failures,
            },
        )
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            os.waitpid(process.pid, 0)
        except (ChildProcessError, ProcessLookupError):
            pass
    else:
        try:
            if admission is None:
                raise OSError(errno.ESRCH, os.strerror(errno.ESRCH))
            _validate_sandbox_process(
                admission.pid,
                admission.start_time_ticks,
                wrapper_identity,
                cgroup,
                full_root=isolation_mode == "full-root",
                require_stopped=True,
            )
            _validate_tracer_target(tracer, admission)
            if isolation_mode == "full-root":
                tracer.attach()
                _validate_sandbox_process(
                    admission.pid,
                    admission.start_time_ticks,
                    wrapper_identity,
                    cgroup,
                    full_root=True,
                    require_stopped=True,
                )
                if admission_write is None:
                    raise OSError(errno.EBADF, os.strerror(errno.EBADF))
                if os.write(admission_write, SANDBOX_ADMISSION_TOKEN) != len(
                    SANDBOX_ADMISSION_TOKEN
                ):
                    raise OSError(errno.EIO, "short sandbox admission write")
                os.close(admission_write)
                admission_write = None
                tracer.resume_root()
            else:
                tracer.begin()
            if mcp is not None:
                mcp.start()
        except (OSError, SandboxIdentityError) as exc:
            error_number = getattr(exc, "errno", None)
            tracer.trace_error = (
                f"ptrace_admission:{error_number}"
                if isinstance(error_number, int)
                else "ptrace_admission:identity"
            )
            if admission_write is not None:
                try:
                    os.close(admission_write)
                except OSError:
                    pass
                admission_write = None
            if "isolation_admission_failure" not in detector.finding_counts:
                _record_isolation_admission_failure(detector)
            detector.mark_telemetry_loss()
            telemetry_incomplete = True
            _write_alert(
                job_id,
                "isolation_setup_failure",
                {
                    "status": _control_status_evidence(control_message),
                    "readiness": {"stage": "tracer_attach"},
                    "failed_requirements": ["sandbox_ready"],
                },
            )
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass

        start = time.monotonic()
        last_sample = start
        killed = False
        namespace_handled = False
        while tracer.active_pids:
            now = time.monotonic()
            if now - start > budgets["wall_clock_sec"] and not killed:
                budget_exhausted = True
                detector.record(
                    make_event(
                        "syscall",
                        "budget_exhausted",
                        "wall_clock",
                        "exit",
                        "anomalous",
                    )
                )
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                killed = True
            if tracer.namespace_escape and not namespace_handled:
                _capture_process_evidence(job_id, tracer.active_pids)
                _mark_host_state(
                    PROJECT_DIR / ".tainted_hosts",
                    job_id,
                    "namespace_escape_suspicion",
                )
                _write_alert(job_id, "namespace_escape_suspicion")
                namespace_handled = True
            if tracer.seccomp_violation and not killed:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                killed = True
            if mcp is not None and mcp.done_at is not None and now - mcp.done_at > 0.05 and not killed:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                killed = True

            while True:
                try:
                    waited_pid, status = os.waitpid(-1, os.WNOHANG | WAIT_WALL)
                except ChildProcessError:
                    tracer.active_pids.clear()
                    break
                if waited_pid <= 0:
                    break
                tracer.process_wait_status(waited_pid, status)

            for key, _ in selector.select(timeout=0.001):
                name = key.data
                stream = key.fileobj
                try:
                    chunk = os.read(stream.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    try:
                        selector.unregister(stream)
                    except Exception:
                        pass
                    continue
                target = raw_stdout if name == "stdout" else raw_stderr
                remaining = budgets["max_output_bytes"] - len(raw_stdout) - len(raw_stderr)
                if remaining > 0:
                    target.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    output_truncated = True
                    telemetry_incomplete = True
                if name == "stdout" and mcp is not None:
                    mcp.feed(chunk[: max(0, remaining)])

            if now - last_sample >= 0.1:
                tracer.sample_resources()
                last_sample = now
            if tracer.trace_error:
                telemetry_incomplete = True
                if not killed:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    killed = True
            if killed and now - start > budgets["wall_clock_sec"] + 2:
                cleanup_pids.update(tracer.active_pids)
                tracer.active_pids.clear()

    # A tracee can exit between its final write and the selector pass that
    # observes it. Drain both pipes before reducing raw bytes to typed signals.
    for stream, target in ((process.stdout, raw_stdout), (process.stderr, raw_stderr)):
        if stream is None:
            continue
        while True:
            try:
                chunk = os.read(stream.fileno(), 65536)
            except BlockingIOError:
                break
            if not chunk:
                break
            remaining = budgets["max_output_bytes"] - len(raw_stdout) - len(raw_stderr)
            if remaining > 0:
                target.extend(chunk[:remaining])
            if len(chunk) > max(remaining, 0):
                output_truncated = True
                telemetry_incomplete = True
            if stream is process.stdout and mcp is not None:
                mcp.feed(chunk[: max(remaining, 0)])

    try:
        selector.close()
    finally:
        if admission_write is not None:
            try:
                os.close(admission_write)
            except OSError:
                pass
            admission_write = None
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass

    raw_output = bytes(raw_stdout + raw_stderr)
    persuasion = scan_instruction_patterns(raw_output)
    if persuasion:
        detector.record(
            make_event(
                "syscall",
                "codex_manipulation",
                "instruction_pattern_in_raw_output",
                "write",
                "known_bad",
            )
        )
        _write_alert(job_id, "codex_manipulation")
    if output_truncated:
        detector.mark_telemetry_loss()
        _write_alert(job_id, "telemetry_loss", {"output_truncated": True})
    if tracer.trace_error:
        detector.mark_telemetry_loss()
        _write_alert(job_id, "telemetry_loss", {"trace_error": tracer.trace_error})
    if tracer.namespace_escape:
        _write_alert(job_id, "namespace_escape_suspicion")

    # Separate a completed payload observation from interpreter-startup and
    # snapshot/library-load failure.  An admitted sandbox that never exec'd
    # the payload interpreter, or whose interpreter died in the loader before
    # the payload ran, produced no execution evidence; only an empty one.
    # Telemetry loss and real findings take precedence: they already carry
    # fail-closed weight, and payload output mimicking loader errors cannot
    # downgrade a verdict.
    payload_exec_observed = bool(tracer.exec_completed_pids)
    observation_failure: str | None = None
    observation_diagnostic = ""
    if not isolation_failures and not detector.finding_counts:
        load_failure, stderr_excerpt = _observation_load_diagnostic(bytes(raw_stderr))
        if not payload_exec_observed:
            observation_failure = "interpreter_startup"
            observation_diagnostic = stderr_excerpt
        elif load_failure:
            observation_failure = load_failure
            observation_diagnostic = stderr_excerpt
    if observation_failure is not None:
        detector.record(
            make_event(
                "syscall",
                "payload_observation_incomplete",
                observation_failure,
                "exit",
                "anomalous",
            )
        )
        telemetry_incomplete = True
        _write_alert(
            job_id,
            "payload_observation_incomplete",
            {
                "failure_class": observation_failure,
                "exec_observed": payload_exec_observed,
                "diagnostic": observation_diagnostic,
            },
        )

    cleanup_pids.update(tracer.active_pids)
    if admission is not None:
        admission.close()
    purge = _cleanup_legacy_resources(
        process.pid,
        cgroup,
        job_dir,
        tracked_pids=cleanup_pids,
    )
    try:
        process.poll()
    except (ChildProcessError, OSError):
        pass
    if not purge["verified_externally"]:
        detector.record(
            make_event(
                "syscall",
                "purge_failure",
                "legacy_cleanup_postcondition_failed",
                "exit",
                "known_bad",
            )
        )
        telemetry_incomplete = True
        _write_alert(
            job_id,
            "purge_uncertainty",
            {
                "processes_remaining": purge["processes_remaining"],
                "remaining_host_resources": purge["remaining_host_resources"],
            },
        )
        _mark_host_state(
            PROJECT_DIR / ".decommissioned_hosts",
            job_id,
            "purge_uncertainty",
        )

    if telemetry_incomplete or detector.telemetry_incomplete:
        uncertainty = 1.0
    elif budget_exhausted:
        uncertainty = 0.3
    elif detector.finding_counts.get("timing_evasion", 0) > 500:
        uncertainty = 0.5
    else:
        uncertainty = 0.0

    try:
        outward_report = broker.build_report(uncertainty=uncertainty)
    except Exception as exc:
        detector.record(
            make_event(
                "syscall", "broker_failure", "egress_schema", "write", "known_bad"
            )
        )
        broker.granted = []
        broker.denied = list(broker.requested)
        _write_alert(job_id, "broker_failure", {"error": type(exc).__name__})
        try:
            outward_report = broker.build_report(uncertainty=1.0)
        except Exception:
            outward_report = {
                "risk_level": "hostile",
                "evidence": [
                    {
                        "tap_category": "syscall_class",
                        "rule_id": "broker_failure",
                        "count": 1,
                    }
                ],
                "capabilities_requested": list(broker.requested),
                "destinations": [],
                "canaries_tripped": [],
                "uncertainty": 1.0,
            }

    gate = apply_scoring_matrix(outward_report, OVERRIDE_PATH, job_id)
    if gate["final_decision"] == "DENY" and raw_output:
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        quarantine = QUARANTINE_DIR / f"{job_id}.raw"
        quarantine.write_bytes(raw_output)
        quarantine.chmod(0o600)

    canaries_touched = {}
    for name in sorted(canary_paths or {"canary_cred_aws": "", "canary_cred_ssh": "", "canary_file": "", "canary_tmp": ""}):
        if name in detector.canaries:
            canaries_touched[name] = f"TOUCHED at t+{detector.canaries[name]:.3f}s"
        else:
            canaries_touched[name] = "untouched"

    observation = None
    if not isolation_failures:
        if observation_failure is not None:
            observation = {
                "status": "EVALUATION_INCOMPLETE",
                "exec_observed": payload_exec_observed,
                "failure_class": observation_failure,
                "diagnostic": observation_diagnostic,
            }
        elif not (telemetry_incomplete or detector.telemetry_incomplete):
            # Telemetry-loss and purge-failure runs already carry their own
            # fail-closed findings; the observation section would add nothing.
            observation = {
                "status": "COMPLETE",
                "exec_observed": payload_exec_observed,
                "failure_class": None,
                "diagnostic": "",
            }

    receipt = create_receipt(
        identity={
            "job_id": job_id,
            "artifact_sha256": sha256_file(artifact),
            "artifact_type": artifact_type,
            "submitted_by": submitted_by,
            "received_at": received_at,
        },
        snapshot_policy={
            "snapshot_sha256": manifest["sha256"],
            "snapshot_verified_by": "host-observer (external)",
            "policy_version": policy.get("policy_version", "cindermote-hotcell-v1.1"),
            "policy_hash": _policy_hash(policy),
        },
        isolation={
            "mode": isolation_mode,
            **isolation_controls,
        },
        budgets_granted={
            "wall_clock_sec": budgets["wall_clock_sec"],
            "cpu_vcpu": budgets["cpu_vcpu"],
            "ram_mib": budgets["ram_mib"],
            "syscalls": "capped",
            "fs_writes": "RAM overlay only",
        },
        capabilities={
            "requested": broker.requested,
            "granted": broker.granted,
            "denied": broker.denied,
        },
        telemetry_summary=tracer.telemetry_summary(),
        canaries_touched=canaries_touched,
        destinations_attempted=dict(sorted(detector.destinations.items())),
        detector_findings=detector.findings(),
        gate=gate,
        outward_report=outward_report,
        purge=purge,
        telemetry_incomplete=telemetry_incomplete or detector.telemetry_incomplete,
        budget_exhausted=budget_exhausted,
        residual_uncertainty=uncertainty,
        key_path=OBSERVER_KEY_PATH,
        mcp_protocol=mcp.receipt() if mcp is not None else None,
        observation=observation,
        active_policy=policy,
    )
    RECEIPTS_DIR.mkdir(parents=True, exist_ok=True)
    write_receipt(
        RECEIPTS_DIR / f"{job_id}.json",
        receipt,
        active_policy=policy,
    )
    return receipt


def _cli() -> int:
    parser = argparse.ArgumentParser(description="Cindermote Hotcell v1.1")
    parser.add_argument("--bootstrap-snapshot", action="store_true")
    parser.add_argument("--artifact")
    parser.add_argument("--artifact-type", choices=sorted(VALID_ARTIFACT_TYPES))
    parser.add_argument("--browser-url")
    parser.add_argument("--authorized-origin", action="append", default=[])
    parser.add_argument("--firecracker-preflight", action="store_true")
    parser.add_argument("--policy")
    parser.add_argument("--sandbox-child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--job-dir", help=argparse.SUPPRESS)
    parser.add_argument("--snapshot", help=argparse.SUPPRESS)
    parser.add_argument("--budgets", help=argparse.SUPPRESS)
    parser.add_argument("--isolation-mode", help=argparse.SUPPRESS)
    parser.add_argument("--require-mlock", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.sandbox_child:
        return _sandbox_child(args)
    if args.bootstrap_snapshot:
        manifest = bootstrap_snapshot()
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 0
    if args.firecracker_preflight:
        report = preflight_firecracker(profile="browser")
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        return 0 if report.ready else 2
    if args.browser_url:
        if args.artifact or args.artifact_type:
            parser.error("--browser-url cannot be combined with --artifact")
        request = make_probe_request(
            args.browser_url,
            authorized_origins=args.authorized_origin or None,
        )
        receipt = detonate_browser_probe(request, args.policy)
        print(json.dumps(receipt, indent=2, sort_keys=True))
        return 0
    if not args.artifact or not args.artifact_type:
        parser.error("--artifact and --artifact-type are required (or use --browser-url)")
    receipt = detonate(args.artifact, args.artifact_type, args.policy)
    print(json.dumps(receipt, indent=2, sort_keys=True))
    # ALLOW and DENY are completed evaluations; anything else (e.g.
    # EVALUATION_INCOMPLETE) means no verdict was rendered — exit non-success.
    return 0 if receipt.get("gate", {}).get("final_decision") in {"ALLOW", "DENY"} else 2


if __name__ == "__main__":
    raise SystemExit(_cli())
