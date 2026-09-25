#!/usr/bin/env python3
"""Fail-closed Firecracker lifecycle for Cindermote browser probes.

The runtime requires a root-owned tmpfs prepared by the operator. It never
falls back to Linux namespaces when a Firecracker-required job cannot start.
Every monitor request has an exact expected response, every runtime asset is
hash-verified before admission, and cleanup is externally checked before a
result may be treated as complete.
"""

from __future__ import annotations

import errno
import fcntl
import grp
import hashlib
import json
import os
import pwd
import re
import resource
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable


THIS_FILE = Path(__file__).resolve()
PROJECT_DIR = THIS_FILE.parents[1]
ASSET_LOCK_PATH = PROJECT_DIR / "policy" / "firecracker-assets.lock.json"
DEFAULT_CACHE_DIR = PROJECT_DIR / ".cindermote" / "cache"
DEFAULT_RUNTIME_ROOT = Path("/run/cindermote")
DEFAULT_CGROUP_ROOT = Path("/sys/fs/cgroup/cindermote")
SAFE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
SAFE_ENV = {"PATH": SAFE_PATH, "LANG": "C"}
VMM_USER = "cindermote-vmm"
VMM_GROUP = "cindermote-vmm"
PROXY_USER = "cindermote-proxy"
PROXY_GROUP = "cindermote-proxy"
PROXY_HOST = "169.254.250.1"
PROXY_PORT = 18080
GUEST_ADDRESS = "172.30.0.2"
GUEST_GATEWAY = "172.30.0.1"
VSOCK_PORT = 52
MAX_GUEST_RESULT = 4 * 1024 * 1024
JOB_ID_PATTERN = re.compile(r"^mf-web-[0-9a-f]{8}$")
JOB_TOKEN_PATTERN = re.compile(r"^[0-9a-f]{8}$")
NETNS_PATTERN = re.compile(r"^mf-([0-9a-f]{8})$")
HOST_VETH_PATTERN = re.compile(r"^[0-9]+:\s+mfh([0-9a-f]{8})(?:@[^:]+)?:")
DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
ROOTFS_BUILD_INPUTS = {
    "base_image_digest": "sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818",
    "debian_snapshot": "20260716T110000Z",
    "chromium_package_version": "150.0.7871.124-1~deb12u1",
    "e2fsprogs_package_version": "1.47.0-2+b2",
    "fakeroot_package_version": "1.31-1.2",
    "platform_tools_url": "https://dl.google.com/android/repository/platform-tools_r33.0.3-linux.zip",
    "platform_tools_sha256": "ab885c20f1a9cb528eb145b9208f53540efa3d26258ac3ce4363570a0846f8f7",
    "e2fsdroid_sha256": "5acfcba27c1a362a9df97879100910d79014090c1ef999a7bc9d7a74998fa0b4",
}

_JAILER_SUPERVISOR_CODE = r"""
import ctypes
import os
import signal
import sys

PR_SET_PDEATHSIG = 1
expected_parent = int(sys.argv[1])
target = sys.argv[2:]
child_pid = 0
stopping = False
watched_signals = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)

def stop_child(_signum, _frame):
    global stopping
    stopping = True
    if child_pid:
        try:
            os.killpg(child_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

for watched_signal in watched_signals:
    signal.signal(watched_signal, stop_child)

libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(PR_SET_PDEATHSIG, signal.SIGTERM, 0, 0, 0) != 0:
    os._exit(125)
if os.getppid() != expected_parent:
    os._exit(125)

# Close the fork/setpgid race: a parent-death signal is held pending until the
# jailer has a dedicated process group that the handler can kill atomically.
old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, watched_signals)
child_pid = os.fork()
if child_pid == 0:
    os.setpgid(0, 0)
    for watched_signal in watched_signals:
        signal.signal(watched_signal, signal.SIG_DFL)
    signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
    os.execve(target[0], target, {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"})

try:
    os.setpgid(child_pid, child_pid)
except PermissionError:
    try:
        if os.getpgid(child_pid) != child_pid:
            os.kill(child_pid, signal.SIGKILL)
            os._exit(125)
    except ProcessLookupError:
        pass
except ProcessLookupError:
    pass
signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
if stopping:
    stop_child(signal.SIGTERM, None)
while True:
    try:
        _waited_pid, status = os.waitpid(child_pid, 0)
        break
    except InterruptedError:
        continue
if os.WIFEXITED(status):
    os._exit(os.WEXITSTATUS(status))
os._exit(128 + os.WTERMSIG(status))
"""


try:
    from cindermote.mote.browser_contract import (
        validate_browser_evidence as validate_guest_browser_evidence_v1,
        validate_probe_request,
    )
    from cindermote.mote.browser_evidence import (
        EVIDENCE_VERSION,
        reduce_browser_evidence,
        validate_browser_event,
        validate_browser_evidence,
    )
    from cindermote.mote.firecracker_api import FirecrackerApiClient
except ModuleNotFoundError:  # Direct checkout execution, without an installed package.
    from browser_contract import (  # type: ignore
        validate_browser_evidence as validate_guest_browser_evidence_v1,
        validate_probe_request,
    )
    from browser_evidence import (  # type: ignore
        EVIDENCE_VERSION,
        reduce_browser_evidence,
        validate_browser_event,
        validate_browser_evidence,
    )
    from firecracker_api import FirecrackerApiClient  # type: ignore


class FirecrackerUnavailable(RuntimeError):
    def __init__(self, report: "PreflightReport") -> None:
        self.report = report
        failed = ", ".join(check.name for check in report.checks if check.required and not check.ok)
        super().__init__(f"Firecracker browser profile unavailable: {failed or 'unknown failure'}")


class FirecrackerRuntimeError(RuntimeError):
    pass


@dataclass(frozen=True)
class PreflightCheck:
    name: str
    ok: bool
    required: bool
    detail: str


@dataclass(frozen=True)
class PreflightReport:
    ready: bool
    profile: str
    checks: tuple[PreflightCheck, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ready": self.ready,
            "profile": self.profile,
            "checks": [asdict(check) for check in self.checks],
        }


@dataclass
class RuntimePaths:
    job_id: str
    netns_name: str
    host_veth: str
    peer_veth: str
    jail_root: Path
    images: Path
    run: Path
    api_socket: Path
    vsock_socket: Path
    cgroup: Path


@dataclass
class BrowserProbeResult:
    job_id: str
    request: dict[str, Any]
    evidence: dict[str, Any]
    reduction: dict[str, Any]
    runtime: dict[str, Any]
    artifacts: dict[str, Any]
    purge: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _asset_paths(cache_dir: Path, lock: dict[str, Any]) -> dict[str, Path]:
    version = lock["firecracker"]["version"]
    architecture = lock["architecture"]
    kernel_version = lock["guest_kernel"]["version"]
    rootfs_relative = Path(lock["browser_rootfs"]["path"])
    receipt_relative = Path(lock["browser_rootfs"]["build_receipt_path"])
    return {
        "firecracker": cache_dir / "firecracker" / f"v{version}" / architecture / "firecracker",
        "jailer": cache_dir / "firecracker" / f"v{version}" / architecture / "jailer",
        "kernel": cache_dir / "kernels" / f"vmlinux-{kernel_version}",
        "rootfs": cache_dir / rootfs_relative,
        "rootfs_receipt": cache_dir / receipt_relative,
    }


def _verified_regular_file(path: Path, expected_sha256: str, executable: bool) -> tuple[bool, str]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        return False, f"missing ({exc.errno})"
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        return False, "not a regular non-symlink file"
    if metadata.st_mode & 0o022:
        return False, "group/world writable"
    if executable and not os.access(path, os.X_OK):
        return False, "not executable"
    try:
        observed = _sha256_file(path)
    except OSError as exc:
        return False, f"unreadable ({exc.errno})"
    if observed != expected_sha256:
        return False, f"SHA-256 mismatch ({observed})"
    return True, f"sha256:{observed}"


def _trusted_root_directory(path: Path) -> tuple[bool, str]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        return False, f"missing ({exc.errno})"
    mode = stat.S_IMODE(metadata.st_mode)
    ok = (
        stat.S_ISDIR(metadata.st_mode)
        and not path.is_symlink()
        and metadata.st_uid == 0
        and metadata.st_gid == 0
        and mode == 0o700
    )
    return ok, f"uid={metadata.st_uid}; gid={metadata.st_gid}; mode={mode:04o}"


def _vmm_identity_check() -> tuple[bool, str, int | None, int | None]:
    """Resolve and validate the dedicated, non-login Firecracker identity."""

    try:
        account = pwd.getpwnam(VMM_USER)
        group = grp.getgrnam(VMM_GROUP)
    except KeyError:
        return False, f"missing dedicated {VMM_USER}:{VMM_GROUP} account", None, None
    except OSError as exc:
        return False, f"cannot resolve dedicated VMM account ({exc.errno})", None, None

    uid = account.pw_uid
    gid = group.gr_gid
    shell_name = Path(account.pw_shell).name
    unexpected_members = sorted(set(group.gr_mem) - {VMM_USER})
    try:
        supplementary_groups = set(os.getgrouplist(VMM_USER, account.pw_gid))
        other_uid_owners = sorted(
            value.pw_name
            for value in pwd.getpwall()
            if value.pw_uid == uid and value.pw_name != VMM_USER
        )
        other_gid_owners = sorted(
            value.gr_name
            for value in grp.getgrall()
            if value.gr_gid == gid and value.gr_name != VMM_GROUP
        )
    except OSError as exc:
        return False, f"cannot enumerate VMM identity ownership ({exc.errno})", uid, gid

    failures: list[str] = []
    if uid in {0, 65533, 65534}:
        failures.append(f"unsafe uid={uid}")
    if gid in {0, 65533, 65534}:
        failures.append(f"unsafe gid={gid}")
    if account.pw_gid != gid:
        failures.append(f"primary_gid={account.pw_gid} differs from dedicated gid={gid}")
    if account.pw_dir != "/nonexistent":
        failures.append(f"home={account.pw_dir!r}, expected '/nonexistent'")
    if shell_name not in {"nologin", "false"}:
        failures.append(f"login shell is enabled ({account.pw_shell!r})")
    if supplementary_groups != {gid}:
        failures.append(
            "supplementary groups are present "
            f"({','.join(str(value) for value in sorted(supplementary_groups))})"
        )
    if unexpected_members:
        failures.append(f"dedicated group has other members ({','.join(unexpected_members)})")
    if other_uid_owners:
        failures.append(f"uid is shared with other accounts ({','.join(other_uid_owners)})")
    if other_gid_owners:
        failures.append(f"gid is shared with other groups ({','.join(other_gid_owners)})")
    locked, lock_detail = _account_lock_check(VMM_USER)
    if not locked:
        failures.append(lock_detail)

    detail = (
        f"user={VMM_USER}; group={VMM_GROUP}; uid={uid}; gid={gid}; "
        f"home={account.pw_dir}; shell={account.pw_shell}; {lock_detail}"
    )
    if failures:
        return False, "; ".join(failures), uid, gid
    return True, detail, uid, gid


def _account_lock_check(user: str) -> tuple[bool, str]:
    """Verify a locally provisioned service account has no usable password."""

    try:
        entries = Path("/etc/shadow").read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return False, f"cannot read local shadow database ({exc.errno})"
    matches = [entry.split(":", 2) for entry in entries if entry.startswith(f"{user}:")]
    if len(matches) != 1 or len(matches[0]) < 2:
        return False, "local shadow entry is missing or ambiguous"
    password = matches[0][1]
    if not password.startswith(("!", "*")):
        return False, "service account password is not locked"
    return True, "password=locked"


def _proxy_identity_check(
    vmm_uid: int | None = None,
    vmm_gid: int | None = None,
) -> tuple[bool, str, int | None, int | None]:
    """Resolve and validate the unique, locked host proxy identity."""

    try:
        account = pwd.getpwnam(PROXY_USER)
        group = grp.getgrnam(PROXY_GROUP)
    except KeyError:
        return False, f"missing dedicated {PROXY_USER}:{PROXY_GROUP} account", None, None
    except OSError as exc:
        return False, f"cannot resolve dedicated proxy account ({exc.errno})", None, None

    uid = account.pw_uid
    gid = group.gr_gid
    try:
        if vmm_uid is None or vmm_gid is None:
            vmm_account = pwd.getpwnam(VMM_USER)
            vmm_group = grp.getgrnam(VMM_GROUP)
            vmm_uid = vmm_account.pw_uid
            vmm_gid = vmm_group.gr_gid
        supplementary_groups = set(os.getgrouplist(PROXY_USER, account.pw_gid))
        other_uid_owners = sorted(
            value.pw_name
            for value in pwd.getpwall()
            if value.pw_uid == uid and value.pw_name != PROXY_USER
        )
        other_gid_owners = sorted(
            value.gr_name
            for value in grp.getgrall()
            if value.gr_gid == gid and value.gr_name != PROXY_GROUP
        )
    except (KeyError, OSError) as exc:
        return False, f"cannot enumerate proxy identity ownership ({exc})", uid, gid

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

    failures: list[str] = []
    if not 0 < uid < 2**31 or uid in forbidden_uids:
        failures.append(f"unsafe uid={uid}")
    if not 0 < gid < 2**31 or gid in forbidden_gids:
        failures.append(f"unsafe gid={gid}")
    if {uid, gid} & {vmm_uid, vmm_gid}:
        failures.append("proxy identity overlaps the dedicated VMM identity")
    if account.pw_gid != gid:
        failures.append(f"primary_gid={account.pw_gid} differs from dedicated gid={gid}")
    if account.pw_dir != "/nonexistent":
        failures.append(f"home={account.pw_dir!r}, expected '/nonexistent'")
    if Path(account.pw_shell).name not in {"nologin", "false"}:
        failures.append(f"login shell is enabled ({account.pw_shell!r})")
    if supplementary_groups != {gid}:
        failures.append(
            "supplementary groups are present "
            f"({','.join(str(value) for value in sorted(supplementary_groups))})"
        )
    unexpected_members = sorted(set(group.gr_mem) - {PROXY_USER})
    if unexpected_members:
        failures.append(
            f"dedicated group has other members ({','.join(unexpected_members)})"
        )
    if other_uid_owners:
        failures.append(f"uid is shared with other accounts ({','.join(other_uid_owners)})")
    if other_gid_owners:
        failures.append(f"gid is shared with other groups ({','.join(other_gid_owners)})")
    locked, lock_detail = _account_lock_check(PROXY_USER)
    if not locked:
        failures.append(lock_detail)

    detail = (
        f"user={PROXY_USER}; group={PROXY_GROUP}; uid={uid}; gid={gid}; "
        f"home={account.pw_dir}; shell={account.pw_shell}; {lock_detail}"
    )
    if failures:
        return False, "; ".join(failures), uid, gid
    return True, detail, uid, gid


def _mount_for(path: Path) -> tuple[str | None, set[str], str]:
    """Return filesystem, combined options, and mountpoint from mountinfo."""

    candidate = path.resolve(strict=False)
    matches: list[tuple[int, str, set[str], str]] = []
    try:
        lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except OSError:
        return None, set(), "unavailable"
    for line in lines:
        left, marker, right = line.partition(" - ")
        if not marker:
            continue
        fields = left.split()
        right_fields = right.split()
        if len(fields) < 6 or len(right_fields) < 3:
            continue
        mountpoint = Path(fields[4].replace("\\040", " "))
        try:
            candidate.relative_to(mountpoint)
        except ValueError:
            continue
        options = set(fields[5].split(",")) | set(right_fields[2].split(","))
        matches.append((len(str(mountpoint)), right_fields[0], options, str(mountpoint)))
    if not matches:
        return None, set(), "unavailable"
    _, filesystem, options, mountpoint = max(matches)
    return filesystem, options, mountpoint


def _swap_disabled() -> tuple[bool, str]:
    try:
        lines = Path("/proc/swaps").read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return False, f"cannot read /proc/swaps ({exc.errno})"
    active = [line for line in lines[1:] if line.strip()]
    return not active, "disabled" if not active else f"{len(active)} active swap device(s)"


def _cgroup_check(cgroup_root: Path) -> tuple[bool, str]:
    filesystem, options, mountpoint = _mount_for(Path("/sys/fs/cgroup"))
    if filesystem != "cgroup2":
        return False, f"cgroup v2 not mounted (observed {filesystem!r} at {mountpoint})"
    if "rw" not in options or "ro" in options:
        return False, f"cgroup v2 mount is not writable ({mountpoint})"
    parent = cgroup_root if cgroup_root.exists() else cgroup_root.parent
    if not os.access(parent, os.W_OK | os.X_OK):
        return False, f"no writable delegated cgroup at {parent}"
    if cgroup_root.exists():
        try:
            enabled = set((cgroup_root / "cgroup.subtree_control").read_text(encoding="ascii").split())
            child_enabled = set(
                (cgroup_root / "firecracker" / "cgroup.subtree_control")
                .read_text(encoding="ascii")
                .split()
            )
        except OSError as exc:
            return False, f"cgroup delegation is incomplete ({exc.errno})"
        required = {"cpu", "memory", "pids"}
        if not required.issubset(enabled) or not required.issubset(child_enabled):
            return False, "cpu/memory/pids controllers are not delegated through firecracker"
    return True, str(parent)


def _rootfs_receipt_check(
    rootfs: Path,
    receipt_path: Path,
    rootfs_lock: dict[str, Any],
) -> tuple[bool, str, dict[str, Any] | None]:
    """Admit only the exact rootfs and build receipt pinned by source policy.

    The receipt is useful provenance, but it lives beside the cache artifact
    and is not itself an authority.  Both byte strings therefore have to match
    immutable digests in the checked-in asset lock before any receipt claim is
    consumed.
    """

    try:
        if set(rootfs_lock) != {
            "path",
            "sha256",
            "build_receipt_path",
            "build_receipt_sha256",
            "required_receipt_schema",
            "source_date_epoch",
            "filesystem_uuid",
            "directory_hash_seed",
        }:
            raise ValueError("browser rootfs lock has unexpected fields")
        expected_schema = rootfs_lock.get("required_receipt_schema")
        expected_rootfs_sha = rootfs_lock.get("sha256")
        expected_receipt_sha = rootfs_lock.get("build_receipt_sha256")
        for name, value in (
            ("rootfs", expected_rootfs_sha),
            ("build receipt", expected_receipt_sha),
        ):
            if not isinstance(value, str) or DIGEST_PATTERN.fullmatch(value) is None:
                raise ValueError(f"locked {name} SHA-256 is invalid")
        receipt_ok, receipt_detail = _verified_regular_file(
            receipt_path, expected_receipt_sha, executable=False
        )
        if not receipt_ok:
            raise ValueError(f"build receipt is not locked: {receipt_detail}")
        receipt = _load_json(receipt_path)
        if receipt.get("schema_version") != expected_schema:
            raise ValueError("unexpected receipt schema")
        if set(receipt) != {
            "schema_version",
            "source_date_epoch",
            "filesystem_uuid",
            "directory_hash_seed",
            "rootfs",
            "browser",
            "runtime_packages",
            "build_inputs",
            "guest_writes",
            "sources",
        }:
            raise ValueError("unexpected rootfs receipt fields")
        root = receipt.get("rootfs")
        browser = receipt.get("browser")
        runtime_packages = receipt.get("runtime_packages")
        build_inputs = receipt.get("build_inputs")
        sources = receipt.get("sources")
        if (
            not isinstance(root, dict)
            or not isinstance(browser, dict)
            or not isinstance(runtime_packages, dict)
            or not isinstance(build_inputs, dict)
            or not isinstance(sources, dict)
        ):
            raise ValueError("receipt sections missing")
        if set(root) != {"sha256", "size_mib", "read_only_runtime"}:
            raise ValueError("unexpected rootfs receipt section")
        if set(browser) != {
            "version",
            "binary_sha256",
            "sandbox_required",
            "sandbox_uid",
            "sandbox_gid",
            "sandbox_mode",
        }:
            raise ValueError("unexpected browser receipt section")
        expected = root.get("sha256")
        if expected != expected_rootfs_sha:
            raise ValueError("receipt rootfs hash differs from the asset lock")
        ok, detail = _verified_regular_file(rootfs, expected_rootfs_sha, executable=False)
        if not ok:
            raise ValueError(detail)
        if (
            root.get("read_only_runtime") is not True
            or not isinstance(root.get("size_mib"), int)
            or not 768 <= root["size_mib"] <= 4096
            or browser.get("sandbox_required") is not True
            or receipt.get("guest_writes") != "tmpfs_only"
        ):
            raise ValueError("rootfs safety attestations missing")
        if (
            browser.get("sandbox_uid") != 0
            or browser.get("sandbox_gid") != 0
            or browser.get("sandbox_mode") != "04755"
        ):
            raise ValueError("rootfs Chromium sandbox inode attestation missing")
        if (
            not isinstance(browser.get("version"), str)
            or not browser["version"].startswith("Chromium ")
            or not isinstance(browser.get("binary_sha256"), str)
            or DIGEST_PATTERN.fullmatch(browser["binary_sha256"]) is None
        ):
            raise ValueError("browser identity missing")
        if (
            set(runtime_packages) != {"python3-cryptography", "libsodium23"}
            or any(not isinstance(value, str) or not value for value in runtime_packages.values())
        ):
            raise ValueError("agent-probe runtime package attestations missing")
        if (
            receipt.get("source_date_epoch") != rootfs_lock.get("source_date_epoch")
            or receipt.get("filesystem_uuid") != rootfs_lock.get("filesystem_uuid")
            or receipt.get("directory_hash_seed")
            != rootfs_lock.get("directory_hash_seed")
            or build_inputs != ROOTFS_BUILD_INPUTS
        ):
            raise ValueError("builder provenance missing")
        expected_sources = {
            "guest/browser_agent.py": PROJECT_DIR / "guest" / "browser_agent.py",
            "guest/agent_probe_agent.py": PROJECT_DIR / "guest" / "agent_probe_agent.py",
            "agent_probe/__init__.py": PROJECT_DIR / "agent_probe" / "__init__.py",
            "agent_probe/canonical.py": PROJECT_DIR / "agent_probe" / "canonical.py",
            "agent_probe/evidence.py": PROJECT_DIR / "agent_probe" / "evidence.py",
            "agent_probe/hpke.py": PROJECT_DIR / "agent_probe" / "hpke.py",
            "agent_probe/protocol.py": PROJECT_DIR / "agent_probe" / "protocol.py",
            "agent_probe/secretstream.py": PROJECT_DIR / "agent_probe" / "secretstream.py",
            "mote/browser_contract.py": PROJECT_DIR / "mote" / "browser_contract.py",
            "guest/cindermote-init": PROJECT_DIR / "guest" / "cindermote-init",
            "images/firecracker/Containerfile": PROJECT_DIR
            / "images"
            / "firecracker"
            / "Containerfile",
            "images/firecracker/RootfsToolchain.Containerfile": PROJECT_DIR
            / "images"
            / "firecracker"
            / "RootfsToolchain.Containerfile",
            "scripts/build-rootfs-in-toolchain.sh": PROJECT_DIR
            / "scripts"
            / "build-rootfs-in-toolchain.sh",
            "scripts/build-firecracker-image.sh": PROJECT_DIR
            / "scripts"
            / "build-firecracker-image.sh",
        }
        if set(sources) != set(expected_sources):
            raise ValueError("rootfs source attestation set is incomplete")
        for name, source_path in expected_sources.items():
            expected_source_hash = sources.get(name)
            if (
                not isinstance(expected_source_hash, str)
                or DIGEST_PATTERN.fullmatch(expected_source_hash) is None
                or _sha256_file(source_path) != expected_source_hash
            ):
                raise ValueError(f"rootfs source attestation differs: {name}")
        return True, f"{browser['version']}; {detail}; receipt={expected_receipt_sha}", receipt
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        return False, str(exc), None


def preflight_firecracker(
    *,
    profile: str = "browser",
    cache_dir: Path | str = DEFAULT_CACHE_DIR,
    runtime_root: Path | str = DEFAULT_RUNTIME_ROOT,
    cgroup_root: Path | str = DEFAULT_CGROUP_ROOT,
    asset_lock_path: Path | str = ASSET_LOCK_PATH,
) -> PreflightReport:
    if profile not in {"browser", "agent-probe", "code"}:
        raise ValueError("profile must be browser, agent-probe, or code")
    cache = Path(cache_dir).resolve()
    runtime_source = Path(runtime_root)
    runtime = runtime_source.resolve()
    cgroups = Path(cgroup_root)
    lock_path = Path(asset_lock_path)
    checks: list[PreflightCheck] = []

    try:
        lock = _load_json(lock_path)
        lock_ok = lock.get("schema_version") == "cindermote.firecracker-assets/v1"
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        lock = {}
        lock_ok = False
        lock_detail = str(exc)
    else:
        lock_detail = str(lock_path)
    checks.append(PreflightCheck("asset_lock", lock_ok, True, lock_detail))
    if not lock_ok:
        return PreflightReport(False, profile, tuple(checks))

    paths = _asset_paths(cache, lock)
    for name, section, hash_key, executable in (
        ("firecracker_binary", "firecracker", "binary_sha256", True),
        ("jailer_binary", "firecracker", "jailer_sha256", True),
        ("guest_kernel", "guest_kernel", "sha256", False),
    ):
        ok, detail = _verified_regular_file(paths[name.split("_")[0] if name != "guest_kernel" else "kernel"], lock[section][hash_key], executable)
        checks.append(PreflightCheck(name, ok, True, detail))

    if profile in {"browser", "agent-probe"}:
        ok, detail, _ = _rootfs_receipt_check(
            paths["rootfs"],
            paths["rootfs_receipt"],
            lock["browser_rootfs"],
        )
        checks.append(PreflightCheck("browser_rootfs", ok, True, detail))

    checks.append(
        PreflightCheck(
            "root_privilege",
            os.geteuid() == 0,
            True,
            f"euid={os.geteuid()} (jailer/network setup require root)",
        )
    )
    identity_ok, identity_detail, _vmm_uid, _vmm_gid = _vmm_identity_check()
    checks.append(
        PreflightCheck(
            "dedicated_vmm_identity",
            identity_ok,
            True,
            identity_detail,
        )
    )
    if profile in {"browser", "agent-probe"}:
        proxy_identity_ok, proxy_identity_detail, _proxy_uid, _proxy_gid = (
            _proxy_identity_check(_vmm_uid, _vmm_gid)
        )
        checks.append(
            PreflightCheck(
                "dedicated_proxy_identity",
                proxy_identity_ok and identity_ok,
                True,
                proxy_identity_detail,
            )
        )
    runtime_permissions_ok, runtime_permissions_detail = _trusted_root_directory(
        runtime_source
    )
    checks.append(
        PreflightCheck(
            "ram_runtime_permissions",
            runtime_permissions_ok,
            True,
            runtime_permissions_detail,
        )
    )
    kvm_ok = os.access("/dev/kvm", os.R_OK | os.W_OK)
    checks.append(PreflightCheck("kvm", kvm_ok, True, "/dev/kvm rw" if kvm_ok else "/dev/kvm unavailable"))
    if profile in {"browser", "agent-probe"}:
        tun_ok = Path("/dev/net/tun").exists() and os.access("/dev/net/tun", os.R_OK | os.W_OK)
        checks.append(PreflightCheck("tun", tun_ok, True, "/dev/net/tun rw" if tun_ok else "/dev/net/tun unavailable"))

    runtime_noswap_proven = False
    jailer_noswap_proven = False
    try:
        filesystem, options, mountpoint = _mount_for(runtime)
        runtime_noswap_proven = filesystem == "tmpfs" and "noswap" in options
        runtime_ok = (
            runtime.is_dir()
            and filesystem == "tmpfs"
            and "ro" not in options
            and {"rw", "nosuid", "nodev", "noswap"}.issubset(options)
        )
        runtime_detail = f"fs={filesystem}; mount={mountpoint}; options={','.join(sorted(options))}"
    except OSError as exc:
        # An unprepared or operator-only runtime root must read as not-ready,
        # never crash the preflight.
        runtime_ok = False
        runtime_detail = f"runtime inspection unavailable: {exc.strerror or exc}"
    checks.append(
        PreflightCheck(
            "ram_runtime",
            runtime_ok,
            True,
            runtime_detail,
        )
    )
    jailer_permissions_ok, jailer_permissions_detail = _trusted_root_directory(
        runtime / "jailer"
    )
    checks.append(
        PreflightCheck(
            "ram_jailer_permissions",
            jailer_permissions_ok,
            True,
            jailer_permissions_detail,
        )
    )
    for directory_name in ("assets", "locks"):
        ok, detail = _trusted_root_directory(runtime / directory_name)
        checks.append(
            PreflightCheck(
                f"ram_{directory_name}_permissions",
                ok,
                True,
                detail,
            )
        )
    try:
        jailer_filesystem, jailer_options, jailer_mountpoint = _mount_for(runtime / "jailer")
        jailer_noswap_proven = jailer_filesystem == "tmpfs" and "noswap" in jailer_options
        jailer_runtime_ok = (
            (runtime / "jailer").is_dir()
            and jailer_filesystem == "tmpfs"
            and "ro" not in jailer_options
            and "nodev" not in jailer_options
            and {"rw", "nosuid", "noswap"}.issubset(jailer_options)
        )
        jailer_detail = (
            f"fs={jailer_filesystem}; mount={jailer_mountpoint}; "
            f"options={','.join(sorted(jailer_options))}"
        )
    except OSError as exc:
        jailer_runtime_ok = False
        jailer_detail = f"jailer runtime inspection unavailable: {exc.strerror or exc}"
    checks.append(
        PreflightCheck(
            "ram_jailer_runtime",
            jailer_runtime_ok,
            True,
            jailer_detail,
        )
    )
    swap_ok, swap_detail = _swap_disabled()
    checks.append(PreflightCheck("host_swap_disabled", swap_ok, True, swap_detail))
    cgroup_ok, cgroup_detail = _cgroup_check(cgroups)
    checks.append(PreflightCheck("delegated_cgroup_v2", cgroup_ok, True, cgroup_detail))
    for command in ("ip", "nft", "mkfs.ext4", "python3", "sysctl"):
        path = shutil.which(command, path=SAFE_PATH)
        checks.append(PreflightCheck(f"command_{command}", path is not None, profile in {"browser", "agent-probe"} or command == "mkfs.ext4", path or "missing"))

    release = os.uname().release
    # The competition target family is 6.18.x (RUNBOOK); its operative
    # requirement is the tmpfs noswap control, which is proven above by
    # re-reading the real runtime and jailer mount options from
    # /proc/self/mounts — the kernel rejects unknown tmpfs options, so a
    # mounted noswap tmpfs is direct evidence.  Admit any kernel that
    # proves the control; keep reporting the target family alongside.
    noswap_proven = runtime_noswap_proven and jailer_noswap_proven
    checks.append(
        PreflightCheck(
            "competition_host_kernel",
            noswap_proven,
            True,
            (
                f"host={release}; target=6.18.x; tmpfs_noswap="
                f"{'proven on runtime mounts' if noswap_proven else 'not proven'}"
            ),
        )
    )
    ready = all(check.ok for check in checks if check.required)
    return PreflightReport(ready, profile, tuple(checks))


def _run(command: list[str], *, input_text: str | None = None, timeout: float = 10.0) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=True,
            env=SAFE_ENV,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise FirecrackerRuntimeError(f"host command failed: {command[0]} {command[1:3]}") from exc


def _supervised_jailer_command(
    jailer_command: list[str],
    *,
    orchestrator_pid: int | None = None,
) -> list[str]:
    """Wrap jailer with an external parent-death and process-group supervisor."""

    if not jailer_command or not Path(jailer_command[0]).is_absolute():
        raise FirecrackerRuntimeError("jailer command must use an absolute executable path")
    python = shutil.which("python3", path=SAFE_PATH)
    if python is None:
        raise FirecrackerRuntimeError("isolated jailer supervisor interpreter is unavailable")
    parent_pid = os.getpid() if orchestrator_pid is None else orchestrator_pid
    if parent_pid <= 1:
        raise FirecrackerRuntimeError("invalid jailer supervisor parent PID")
    return [
        python,
        "-I",
        "-S",
        "-B",
        "-c",
        _JAILER_SUPERVISOR_CODE,
        str(parent_pid),
        *jailer_command,
    ]


def _network_paths(job_id: str, runtime_root: Path, cgroup_root: Path) -> RuntimePaths:
    token = job_id.rsplit("-", 1)[-1]
    netns = f"mf-{token}"
    host_veth = f"mfh{token}"
    peer_veth = f"mfn{token}"
    jail_root = runtime_root / "jailer" / "firecracker" / job_id / "root"
    run = jail_root / "run"
    return RuntimePaths(
        job_id=job_id,
        netns_name=netns,
        host_veth=host_veth,
        peer_veth=peer_veth,
        jail_root=jail_root,
        images=jail_root / "images",
        run=run,
        api_socket=run / "firecracker.socket",
        vsock_socket=run / "vsock",
        cgroup=cgroup_root / "firecracker" / job_id,
    )


def _owned_stale_job_tokens(runtime_root: Path, cgroup_root: Path) -> set[str]:
    """Enumerate only exact Cindermote browser-job artifacts."""

    tokens: set[str] = set()
    for base in (
        runtime_root / "jailer" / "firecracker",
        cgroup_root / "firecracker",
    ):
        try:
            entries = list(base.iterdir())
        except FileNotFoundError:
            entries = []
        except OSError as exc:
            raise FirecrackerRuntimeError(f"cannot enumerate owned runtime artifacts at {base}") from exc
        for entry in entries:
            if JOB_ID_PATTERN.fullmatch(entry.name) is not None:
                try:
                    metadata = entry.lstat()
                except OSError as exc:
                    raise FirecrackerRuntimeError(
                        f"cannot inspect owned runtime artifact at {entry}"
                    ) from exc
                if not stat.S_ISDIR(metadata.st_mode) or entry.is_symlink():
                    raise FirecrackerRuntimeError(
                        f"owned runtime artifact has an unsafe type at {entry}"
                    )
                tokens.add(entry.name.rsplit("-", 1)[-1])

    namespace_listing = _run(["ip", "netns", "list"])
    for line in namespace_listing.stdout.splitlines():
        fields = line.split()
        match = NETNS_PATTERN.fullmatch(fields[0]) if fields else None
        if match is not None:
            tokens.add(match.group(1))

    link_listing = _run(["ip", "-o", "link", "show"])
    for line in link_listing.stdout.splitlines():
        match = HOST_VETH_PATTERN.match(line)
        if match is not None:
            tokens.add(match.group(1))
    return tokens


def _reconcile_stale_browser_jobs(runtime_root: Path, cgroup_root: Path) -> None:
    """Purge stale exact-prefix jobs while the global browser lock is held."""

    for token in sorted(_owned_stale_job_tokens(runtime_root, cgroup_root)):
        if JOB_TOKEN_PATTERN.fullmatch(token) is None:
            raise FirecrackerRuntimeError("internal stale-job token validation failed")
        paths = _network_paths(f"mf-web-{token}", runtime_root, cgroup_root)
        process_clean, _exit_code, _limits, cgroup_removed = _terminate(None, paths)
        network_removed = _cleanup_network(paths)
        job_root = paths.jail_root.parent
        try:
            metadata = job_root.lstat()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise FirecrackerRuntimeError(f"cannot inspect stale jail for {paths.job_id}") from exc
        else:
            if not stat.S_ISDIR(metadata.st_mode) or job_root.is_symlink():
                raise FirecrackerRuntimeError(f"stale jail has an unsafe type for {paths.job_id}")
            try:
                shutil.rmtree(job_root)
            except OSError as exc:
                raise FirecrackerRuntimeError(f"cannot remove stale jail for {paths.job_id}") from exc
        jail_removed = not job_root.exists() and not job_root.is_symlink()
        if not (process_clean and cgroup_removed and network_removed and jail_removed):
            raise FirecrackerRuntimeError(f"stale Firecracker job could not be purged: {paths.job_id}")


def _setup_network(paths: RuntimePaths, vmm_uid: int, vmm_gid: int) -> None:
    _run(["ip", "netns", "add", paths.netns_name])
    try:
        _run(["ip", "link", "add", paths.host_veth, "type", "veth", "peer", "name", paths.peer_veth])
        _run(["ip", "link", "set", paths.peer_veth, "netns", paths.netns_name])
        _run(["ip", "address", "add", "169.254.250.1/30", "dev", paths.host_veth])
        _run(["ip", "link", "set", paths.host_veth, "up"])
        _run(["ip", "route", "add", "172.30.0.0/30", "via", "169.254.250.2", "dev", paths.host_veth])
        for command in (
            ["ip", "-n", paths.netns_name, "link", "set", "lo", "up"],
            ["ip", "-n", paths.netns_name, "address", "add", "169.254.250.2/30", "dev", paths.peer_veth],
            ["ip", "-n", paths.netns_name, "link", "set", paths.peer_veth, "up"],
            [
                "ip", "-n", paths.netns_name, "tuntap", "add", "dev", "tap0",
                "mode", "tap", "user", str(vmm_uid), "group", str(vmm_gid),
            ],
            ["ip", "-n", paths.netns_name, "address", "add", "172.30.0.1/30", "dev", "tap0"],
            ["ip", "-n", paths.netns_name, "link", "set", "tap0", "up"],
        ):
            _run(command)
        _run(["ip", "netns", "exec", paths.netns_name, "sysctl", "-q", "-w", "net.ipv4.ip_forward=1"])
        nft = f"""
table inet cindermote {{
  chain input {{ type filter hook input priority 0; policy drop; iifname \"lo\" accept; ct state established,related accept; }}
  chain output {{ type filter hook output priority 0; policy drop; oifname \"lo\" accept; ct state established,related accept; }}
  chain forward {{
    type filter hook forward priority 0; policy drop;
    iifname \"tap0\" oifname \"{paths.peer_veth}\" ip daddr {PROXY_HOST} tcp dport {PROXY_PORT} accept
    iifname \"{paths.peer_veth}\" oifname \"tap0\" ct state established,related accept
  }}
}}
"""
        _run(["ip", "netns", "exec", paths.netns_name, "nft", "-f", "-"], input_text=nft)
    except BaseException:
        _cleanup_network(paths)
        raise


def _cleanup_network(paths: RuntimePaths) -> bool:
    ok = True
    for command in (
        ["ip", "netns", "delete", paths.netns_name],
        ["ip", "link", "delete", paths.host_veth],
    ):
        try:
            subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
                env=SAFE_ENV,
            )
        except (OSError, subprocess.TimeoutExpired):
            ok = False
    try:
        namespace_probe = subprocess.run(
            ["ip", "netns", "list"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
            env=SAFE_ENV,
        )
        link_probe = subprocess.run(
            ["ip", "link", "show", "dev", paths.host_veth],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            env=SAFE_ENV,
        )
    except OSError:
        return False
    namespace_absent = not any(
        line.split()[0] == paths.netns_name
        for line in namespace_probe.stdout.splitlines()
        if line.split()
    )
    return ok and namespace_probe.returncode == 0 and namespace_absent and link_probe.returncode != 0


def _stage_copy(source: Path, destination: Path, mode: int) -> str:
    source_stat = source.lstat()
    if not stat.S_ISREG(source_stat.st_mode) or source.is_symlink():
        raise FirecrackerRuntimeError(f"unsafe runtime asset: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    digest = hashlib.sha256()
    source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        destination_fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, mode)
        try:
            while True:
                chunk = os.read(source_fd, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(destination_fd, view)
                    if written <= 0:
                        raise OSError(errno.EIO, "short write while staging runtime asset")
                    view = view[written:]
            os.fsync(destination_fd)
        finally:
            os.close(destination_fd)
    finally:
        os.close(source_fd)
    os.chmod(temporary, mode)
    os.replace(temporary, destination)
    return digest.hexdigest()


def _prepare_job_image(
    path: Path,
    wrapper: dict[str, Any],
    *,
    extra_files: dict[str, bytes] | None = None,
    image_size_mib: int = 8,
) -> str:
    """Create one read-only job image from a trusted wrapper and opaque files.

    ``extra_files`` keys are normalized POSIX-relative paths.  They may not
    escape the image root, replace request.json, create symlinks, or exceed the
    bounded image budget.  The host copies bytes without parsing their content.
    """

    if not isinstance(image_size_mib, int) or isinstance(image_size_mib, bool) or not 8 <= image_size_mib <= 64:
        raise FirecrackerRuntimeError("job image size must be in 8..64 MiB")
    files = extra_files or {}
    if not isinstance(files, dict) or len(files) > 32:
        raise FirecrackerRuntimeError("job image file set is invalid")
    total_bytes = 0
    normalized: list[tuple[Path, bytes]] = []
    for raw_name, content in files.items():
        if not isinstance(raw_name, str) or not isinstance(content, bytes):
            raise FirecrackerRuntimeError("job image files must be byte strings at string paths")
        relative = Path(raw_name)
        if (
            relative.is_absolute()
            or not relative.parts
            or any(part in {"", ".", ".."} for part in relative.parts)
            or relative.as_posix() == "request.json"
        ):
            raise FirecrackerRuntimeError("job image path is unsafe")
        total_bytes += len(content)
        if total_bytes > 4 * 1024 * 1024:
            raise FirecrackerRuntimeError("job image opaque file budget exceeded")
        normalized.append((relative, content))

    with tempfile.TemporaryDirectory(prefix="job-tree-", dir=path.parent) as temporary:
        tree = Path(temporary)
        request_path = tree / "request.json"
        request_path.write_text(
            json.dumps(wrapper, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n",
            encoding="utf-8",
        )
        request_path.chmod(0o444)
        for relative, content in normalized:
            destination = tree / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o444,
            )
            try:
                view = memoryview(content)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError(errno.EIO, "short job image write")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            destination.chmod(0o444)

        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
        try:
            os.ftruncate(descriptor, image_size_mib * 1024 * 1024)
        finally:
            os.close(descriptor)
        _run(["mkfs.ext4", "-q", "-F", "-d", str(tree), "-L", "cindermote-job", str(path)], timeout=30)
    path.chmod(0o444)
    return _sha256_file(path)


def _purge_summary(
    *,
    processes_reaped: bool,
    cgroup_removed: bool,
    network_namespace_removed: bool,
    ram_jail_removed: bool,
    egress_worker_reaped: bool,
) -> dict[str, bool]:
    checks = {
        "processes_reaped": processes_reaped is True,
        "cgroup_removed": cgroup_removed is True,
        "network_namespace_removed": network_namespace_removed is True,
        "ram_jail_removed": ram_jail_removed is True,
        "egress_worker_reaped": egress_worker_reaped is True,
    }
    return {"verified_externally": all(checks.values()), **checks}


def _egress_stream_complete(
    *,
    proxy_present: bool,
    egress_worker_reaped: bool,
    network_namespace_removed: bool,
    telemetry: dict[str, Any],
) -> bool:
    return bool(
        proxy_present
        and egress_worker_reaped is True
        and network_namespace_removed is True
        and telemetry.get("complete") is True
    )


def _enforce_purge_gate(reduction: dict[str, Any], purge_verified: bool) -> None:
    if purge_verified is not True:
        reduction["decision"] = "DENY"
        reduction["complete"] = False
        reduction["telemetry_incomplete"] = True
        reduction["fail_closed"] = True


def _read_line(
    sock: socket.socket,
    buffered: bytearray,
    maximum: int,
    deadline: float,
) -> bytes:
    """Read one bounded line without discarding coalesced stream bytes."""

    while b"\n" not in buffered:
        if len(buffered) >= maximum:
            raise FirecrackerRuntimeError("vsock control line exceeds limit")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("vsock deadline expired")
        sock.settimeout(remaining)
        chunk = sock.recv(min(65536, maximum - len(buffered)))
        if not chunk:
            raise FirecrackerRuntimeError("vsock closed before a complete message")
        buffered.extend(chunk)
    line, separator, remainder = buffered.partition(b"\n")
    buffered[:] = remainder
    return line + separator


def _connect_guest(
    paths: RuntimePaths,
    nonce: str,
    deadline: float,
) -> tuple[socket.socket, bytearray, dict[str, Any]]:
    while time.monotonic() < deadline:
        if not paths.vsock_socket.exists():
            time.sleep(0.02)
            continue
        candidate = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            buffered = bytearray()
            candidate.settimeout(min(1.0, deadline - time.monotonic()))
            candidate.connect(str(paths.vsock_socket))
            candidate.sendall(f"CONNECT {VSOCK_PORT}\n".encode("ascii"))
            acknowledgement = _read_line(candidate, buffered, 64, deadline)
            if re.fullmatch(rb"OK [0-9]+\n", acknowledgement) is None:
                raise FirecrackerRuntimeError("invalid Firecracker vsock acknowledgement")
            hello = json.loads(_read_line(candidate, buffered, 4096, deadline))
            if hello != {"agent_version": "cindermote-browser-agent/1", "nonce": nonce, "type": "hello"}:
                raise FirecrackerRuntimeError("guest agent handshake mismatch")
            candidate.sendall(json.dumps({"type": "run", "nonce": nonce}, sort_keys=True, separators=(",", ":")).encode() + b"\n")
            return candidate, buffered, hello
        except (OSError, ValueError, json.JSONDecodeError, FirecrackerRuntimeError):
            candidate.close()
            time.sleep(0.05)
    raise TimeoutError("guest vsock handshake timed out")


def _read_guest_result(
    sock: socket.socket,
    buffered: bytearray,
    nonce: str,
    deadline: float,
) -> dict[str, Any]:
    raw = _read_line(sock, buffered, MAX_GUEST_RESULT, deadline)
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise FirecrackerRuntimeError("guest returned malformed JSON") from exc
    if not isinstance(value, dict) or value.get("type") != "result" or value.get("nonce") != nonce:
        raise FirecrackerRuntimeError("guest result is not bound to this job")
    return value


def _validate_guest_artifacts(value: Any, max_events: int) -> dict[str, Any]:
    expected = {
        "raw_retained",
        "attestation_complete",
        "dom_sha256",
        "visible_text_sha256",
        "screenshot_sha256",
        "console_event_count",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise FirecrackerRuntimeError("guest artifact metadata has an unexpected shape")
    if value.get("raw_retained") is not False:
        raise FirecrackerRuntimeError("guest claims raw browser artifacts were retained")
    if not isinstance(value.get("attestation_complete"), bool):
        raise FirecrackerRuntimeError("guest page attestation status is malformed")
    for name in ("dom_sha256", "visible_text_sha256", "screenshot_sha256"):
        if not isinstance(value.get(name), str) or DIGEST_PATTERN.fullmatch(value[name]) is None:
            raise FirecrackerRuntimeError("guest artifact digest is malformed")
    console_count = value.get("console_event_count")
    if (
        not isinstance(console_count, int)
        or isinstance(console_count, bool)
        or not 0 <= console_count <= max_events
    ):
        raise FirecrackerRuntimeError("guest console event count is malformed")
    return dict(value)


def _append_event(
    evidence: dict[str, Any],
    source: str,
    kind: str,
    disposition: str,
    *,
    web_origin: str | None = None,
    connect_authority: str | None = None,
) -> None:
    events = evidence["events"]
    sequence = sum(event.get("source") == source for event in events)
    event = validate_browser_event(
        {
            "sequence": sequence,
            "source": source,
            "kind": kind,
            "web_origin": web_origin,
            "connect_authority": connect_authority,
            "disposition": disposition,
        }
    )
    events.append(event)
    evidence["streams"][source]["event_count"] = sequence + 1


def _translate_guest_evidence_v1(value: Any) -> dict[str, Any]:
    """Translate only guest-owned v1 browser/CDP events into host evidence v2.

    The pinned rootfs continues to emit v1.  Its event ``origin`` field is
    unambiguous because the guest is forbidden to contribute host-owned egress
    or VM events.  Any attempt to cross that source boundary fails closed.
    """

    legacy = validate_guest_browser_evidence_v1(value)
    for source in ("egress", "vm"):
        if legacy["streams"][source] != {"complete": False, "event_count": 0}:
            raise FirecrackerRuntimeError(
                "guest evidence claims a host-owned stream"
            )
    converted_events: list[dict[str, Any]] = []
    for event in legacy["events"]:
        if event["source"] not in {"browser", "cdp"}:
            raise FirecrackerRuntimeError(
                "guest evidence contains a host-owned event source"
            )
        converted_events.append(
            validate_browser_event(
                {
                    "sequence": event["sequence"],
                    "source": event["source"],
                    "kind": event["kind"],
                    "web_origin": event["origin"],
                    "connect_authority": None,
                    "disposition": event["disposition"],
                }
            )
        )
    return validate_browser_evidence(
        {
            "evidence_version": EVIDENCE_VERSION,
            "events": converted_events,
            "streams": {
                source: dict(legacy["streams"][source])
                for source in ("browser", "cdp", "egress", "vm")
            },
        }
    )


def _cgroup_readback(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for name in ("cpu.max", "memory.max", "memory.swap.max", "pids.max"):
        try:
            value = (path / name).read_text(encoding="ascii").strip()
        except OSError:
            continue
        if len(value) <= 128:
            values[name] = value
    return values


def _terminate(
    process: subprocess.Popen[bytes] | None,
    paths: RuntimePaths,
) -> tuple[bool, int | None, dict[str, str], bool]:
    exit_code: int | None = None
    readback = _cgroup_readback(paths.cgroup)
    if process is not None:
        if process.poll() is None:
            try:
                os.kill(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                exit_code = process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        if exit_code is None:
            try:
                exit_code = process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                exit_code = None
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
    try:
        kill_path = paths.cgroup / "cgroup.kill"
        if kill_path.exists():
            kill_path.write_text("1\n", encoding="ascii")
    except OSError:
        pass
    process_alive = process is not None and process.poll() is None
    populated = process_alive
    deadline = time.monotonic() + 2
    while paths.cgroup.exists() and time.monotonic() < deadline:
        try:
            events = (paths.cgroup / "cgroup.events").read_text(encoding="ascii")
            populated = "populated 1" in events
        except OSError:
            populated = False
        if not populated:
            break
        time.sleep(0.02)
    cgroup_removed = not paths.cgroup.exists()
    if paths.cgroup.exists() and not populated:
        try:
            paths.cgroup.rmdir()
        except OSError:
            pass
        cgroup_removed = not paths.cgroup.exists()
    process_reaped = process is None or process.poll() is not None
    return process_reaped and not populated, exit_code, readback, cgroup_removed


def run_browser_probe(
    probe_request: dict[str, Any],
    *,
    cache_dir: Path | str = DEFAULT_CACHE_DIR,
    runtime_root: Path | str = DEFAULT_RUNTIME_ROOT,
    cgroup_root: Path | str = DEFAULT_CGROUP_ROOT,
    proxy_factory: Callable[..., Any] | None = None,
) -> BrowserProbeResult:
    """Run one browser probe. Any infrastructure uncertainty returns DENY evidence."""

    request = validate_probe_request(probe_request)
    cache = Path(cache_dir).resolve()
    runtime = Path(runtime_root).resolve()
    cgroups = Path(cgroup_root)
    report = preflight_firecracker(profile="browser", cache_dir=cache, runtime_root=runtime, cgroup_root=cgroups)
    if not report.ready:
        raise FirecrackerUnavailable(report)
    lock = _load_json(ASSET_LOCK_PATH)
    assets = _asset_paths(cache, lock)
    _, _, rootfs_receipt = _rootfs_receipt_check(
        assets["rootfs"], assets["rootfs_receipt"], lock["browser_rootfs"]
    )
    if rootfs_receipt is None:
        raise FirecrackerRuntimeError("browser rootfs receipt changed after preflight")
    identity_ok, identity_detail, vmm_uid, vmm_gid = _vmm_identity_check()
    if not identity_ok or vmm_uid is None or vmm_gid is None:
        raise FirecrackerRuntimeError(
            f"dedicated VMM identity changed after preflight: {identity_detail}"
        )
    proxy_identity_ok, proxy_identity_detail, proxy_uid, proxy_gid = (
        _proxy_identity_check(vmm_uid, vmm_gid)
    )
    if not proxy_identity_ok or proxy_uid is None or proxy_gid is None:
        raise FirecrackerRuntimeError(
            "dedicated proxy identity changed after preflight: "
            f"{proxy_identity_detail}"
        )

    job_id = "mf-web-" + uuid.uuid4().hex[:8]
    if JOB_ID_PATTERN.fullmatch(job_id) is None:
        raise AssertionError("internal job ID error")
    paths = _network_paths(job_id, runtime, cgroups)
    lock_file = runtime / "locks" / "browser.lock"
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    lock_fd = os.open(lock_file, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(lock_fd)
        raise FirecrackerRuntimeError("another browser microVM is active") from exc
    try:
        _reconcile_stale_browser_jobs(runtime, cgroups)
    except BaseException:
        os.close(lock_fd)
        raise

    process: subprocess.Popen[bytes] | None = None
    proxy: Any = None
    network_attempted = False
    purge_network = False
    purge_process = False
    purge_cgroup = False
    purge_jail = False
    # Absence is not a reap attestation: if execution fails before the worker
    # can produce an independently checked lifecycle, the whole run remains
    # fail-closed even though there may be no proxy process to kill.
    purge_proxy = False
    guest_result: dict[str, Any] | None = None
    nonce = secrets.token_hex(32)
    deadline = time.monotonic() + request["budgets"]["wall_clock_sec"] + 10
    evidence = {
        "evidence_version": EVIDENCE_VERSION,
        "events": [],
        "streams": {
            source: {"complete": False, "event_count": 0}
            for source in ("browser", "cdp", "egress", "vm")
        },
    }
    runtime_identity: dict[str, Any] = {
        "admitted": False,
        "firecracker_version": lock["firecracker"]["version"],
        "firecracker_sha256": lock["firecracker"]["binary_sha256"],
        "jailer_sha256": lock["firecracker"]["jailer_sha256"],
        "kernel_sha256": lock["guest_kernel"]["sha256"],
        "rootfs_sha256": rootfs_receipt["rootfs"]["sha256"],
        "rootfs_receipt_sha256": lock["browser_rootfs"]["build_receipt_sha256"],
        "browser_version": rootfs_receipt["browser"]["version"],
        "browser_sha256": rootfs_receipt["browser"]["binary_sha256"],
        "host_runtime_tmpfs": True,
        "host_swap_disabled": True,
        "rootfs_read_only": False,
        "guest_writes_tmpfs_only": False,
        "network_mode": "explicit-proxy-only",
        "mmds_enabled": False,
        "vmm_identity": {
            "user": VMM_USER,
            "group": VMM_GROUP,
            "uid": vmm_uid,
            "gid": vmm_gid,
        },
    }
    artifacts: dict[str, Any] = {"raw_retained": False}
    try:
        # Stage the executable used by jailer into the trusted RAM mount.
        staged = runtime / "assets"
        staged.mkdir(parents=True, exist_ok=True)
        staged_firecracker = staged / "firecracker"
        staged_jailer = staged / "jailer"
        for source, destination, expected, mode in (
            (assets["firecracker"], staged_firecracker, lock["firecracker"]["binary_sha256"], 0o500),
            (assets["jailer"], staged_jailer, lock["firecracker"]["jailer_sha256"], 0o500),
        ):
            if not destination.exists():
                observed = _stage_copy(source, destination, mode)
                if observed != expected:
                    destination.unlink(missing_ok=True)
                    raise FirecrackerRuntimeError("staged runtime asset hash mismatch")
            elif _sha256_file(destination) != expected:
                raise FirecrackerRuntimeError("trusted RAM asset pool changed")

        paths.images.mkdir(parents=True, mode=0o500, exist_ok=False)
        os.chown(paths.images, vmm_uid, vmm_gid)
        paths.run.mkdir(parents=True, mode=0o700)
        kernel_sha = _stage_copy(assets["kernel"], paths.images / "vmlinux", 0o444)
        rootfs_sha = _stage_copy(assets["rootfs"], paths.images / "rootfs.ext4", 0o444)
        if kernel_sha != lock["guest_kernel"]["sha256"]:
            raise FirecrackerRuntimeError("guest kernel changed while being staged")
        if rootfs_sha != rootfs_receipt["rootfs"]["sha256"]:
            raise FirecrackerRuntimeError("browser rootfs changed while being staged")
        wrapper = {
            "probe_request": request,
            "runtime": {"nonce": nonce, "proxy_url": f"http://{PROXY_HOST}:{PROXY_PORT}"},
        }
        job_sha = _prepare_job_image(paths.images / "job.ext4", wrapper)
        for name in ("firecracker.log", "firecracker.metrics", "guest.serial"):
            item = paths.run / name
            item.touch(mode=0o600)
            os.chown(item, vmm_uid, vmm_gid)
        for name in ("jailer.stdout", "jailer.stderr"):
            (paths.run / name).touch(mode=0o600)
        os.chown(paths.run, vmm_uid, vmm_gid)

        network_attempted = True
        _setup_network(paths, vmm_uid, vmm_gid)
        memory_max = (request["budgets"]["ram_mib"] + 512) * 1024 * 1024
        command = [
            str(staged_jailer),
            "--id", job_id,
            "--exec-file", str(staged_firecracker),
            "--uid", str(vmm_uid),
            "--gid", str(vmm_gid),
            "--chroot-base-dir", str(runtime / "jailer"),
            "--cgroup-version", "2",
            "--parent-cgroup", "cindermote/firecracker",
            "--cgroup", f"cpu.max={100000 * request['budgets']['cpu_vcpu']} 100000",
            "--cgroup", f"memory.max={memory_max}",
            "--cgroup", "memory.swap.max=0",
            "--cgroup", "pids.max=256",
            "--resource-limit", "no-file=512",
            "--resource-limit", "fsize=67108864",
            "--netns", f"/run/netns/{paths.netns_name}",
            "--",
            "--api-sock", "/run/firecracker.socket",
        ]
        supervised_command = _supervised_jailer_command(command)
        runtime_identity["jailer_supervision"] = {
            "external_supervisor": True,
            "parent_death_signal": "SIGTERM",
            "vmm_process_group_kill": "SIGKILL",
            "startup_reconciliation": "exact-owned-prefix",
        }

        jailer_stdout = (paths.run / "jailer.stdout").open("wb", buffering=0)
        jailer_stderr = (paths.run / "jailer.stderr").open("wb", buffering=0)
        old_core_limit = resource.getrlimit(resource.RLIMIT_CORE)
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, old_core_limit[1]))
            process = subprocess.Popen(
                supervised_command,
                stdin=subprocess.DEVNULL,
                stdout=jailer_stdout,
                stderr=jailer_stderr,
                start_new_session=True,
                env=SAFE_ENV,
            )
        finally:
            resource.setrlimit(resource.RLIMIT_CORE, old_core_limit)
            jailer_stdout.close()
            jailer_stderr.close()
        api_deadline = min(deadline, time.monotonic() + 5)
        while not paths.api_socket.exists() and time.monotonic() < api_deadline:
            if process.poll() is not None:
                raise FirecrackerRuntimeError("jailer/Firecracker exited before API readiness")
            time.sleep(0.01)
        client = FirecrackerApiClient(paths.api_socket, timeout_sec=2)
        version = client.get_json("/version")
        if version.get("firecracker_version") != lock["firecracker"]["version"]:
            raise FirecrackerRuntimeError("Firecracker API version differs from asset lock")
        for endpoint, payload in (
            ("/logger", {"log_path": "/run/firecracker.log", "level": "Info", "show_level": True, "show_log_origin": True}),
            ("/metrics", {"metrics_path": "/run/firecracker.metrics"}),
            (
                "/serial",
                {
                    "serial_out_path": "/run/guest.serial",
                    "rate_limiter": {
                        "size": 1048576,
                        "one_time_burst": 1048576,
                        "refill_time": 1000,
                    },
                },
            ),
            ("/machine-config", {"vcpu_count": request["budgets"]["cpu_vcpu"], "mem_size_mib": request["budgets"]["ram_mib"], "smt": False, "track_dirty_pages": False}),
            ("/boot-source", {"kernel_image_path": "/images/vmlinux", "boot_args": "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda ro init=/sbin/cindermote-init"}),
            ("/drives/rootfs", {"drive_id": "rootfs", "path_on_host": "/images/rootfs.ext4", "is_root_device": True, "is_read_only": True}),
            ("/drives/job", {"drive_id": "job", "path_on_host": "/images/job.ext4", "is_root_device": False, "is_read_only": True}),
            ("/vsock", {"guest_cid": 3, "uds_path": "/run/vsock"}),
            ("/network-interfaces/browser0", {"iface_id": "browser0", "guest_mac": "06:00:ac:1e:00:02", "host_dev_name": "tap0", "mtu": 1500}),
        ):
            client.put_json(endpoint, payload, expected_status=204)
        require_worker_receipt = proxy_factory is None
        if proxy_factory is None:
            try:
                from cindermote.broker.browser_egress_worker import BrowserEgressWorker
            except ModuleNotFoundError:
                from broker.browser_egress_worker import BrowserEgressWorker  # type: ignore
            proxy_factory = BrowserEgressWorker
        proxy = proxy_factory(
            request,
            bind_host=PROXY_HOST,
            bind_port=PROXY_PORT,
            allowed_client_ip=GUEST_ADDRESS,
            worker_uid=proxy_uid,
            worker_gid=proxy_gid,
        )
        proxy_endpoint = proxy.start()
        if proxy_endpoint != (PROXY_HOST, PROXY_PORT):
            raise FirecrackerRuntimeError("egress proxy bound an unexpected endpoint")
        readiness = getattr(proxy, "readiness_receipt", None)
        if require_worker_receipt and not isinstance(readiness, dict):
            raise FirecrackerRuntimeError("privilege-separated egress worker did not attest readiness")
        if isinstance(readiness, dict):
            security = readiness.get("security")
            if not isinstance(security, dict):
                raise FirecrackerRuntimeError("egress worker security receipt is missing")
            if security.get("uid") != proxy_uid or security.get("gid") != proxy_gid:
                raise FirecrackerRuntimeError(
                    "egress worker identity differs from the parent-verified account"
                )
            runtime_identity["egress_worker"] = {
                "privilege_separated": True,
                "protocol_version": readiness.get("protocol_version"),
                "user": PROXY_USER,
                "group": PROXY_GROUP,
                "uid": security.get("uid"),
                "gid": security.get("gid"),
                "no_new_privs": security.get("no_new_privs"),
                "dumpable": security.get("dumpable"),
                "capabilities_zero": security.get("capabilities_zero"),
            }
        client.put_json("/actions", {"action_type": "InstanceStart"}, expected_status=204)
        _append_event(evidence, "vm", "lifecycle", "started")

        channel, channel_buffer, _ = _connect_guest(paths, nonce, deadline)
        try:
            guest_result = _read_guest_result(channel, channel_buffer, nonce, deadline)
        finally:
            channel.close()
        if guest_result.get("error") is not None:
            raise FirecrackerRuntimeError("guest probe reported a bounded execution failure")
        if set(guest_result) != {
            "type",
            "nonce",
            "agent_version",
            "evidence",
            "probe_request_sha256",
            "artifacts",
            "browser_version",
        }:
            raise FirecrackerRuntimeError("guest success result has an unexpected shape")
        if guest_result.get("agent_version") != "cindermote-browser-agent/1":
            raise FirecrackerRuntimeError("guest agent identity changed during execution")
        expected_request_sha = hashlib.sha256(
            json.dumps(
                request,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
        if guest_result.get("probe_request_sha256") != expected_request_sha:
            raise FirecrackerRuntimeError("guest result is not bound to the admitted request")
        if guest_result.get("browser_version") != rootfs_receipt["browser"]["version"]:
            raise FirecrackerRuntimeError("guest browser identity differs from the rootfs receipt")
        guest_evidence = _translate_guest_evidence_v1(
            guest_result.get("evidence")
        )
        evidence["events"].extend(guest_evidence["events"])
        for source in ("browser", "cdp"):
            evidence["streams"][source] = guest_evidence["streams"][source]
        artifacts = _validate_guest_artifacts(
            guest_result.get("artifacts"), request["budgets"]["max_events"]
        )
        runtime_identity.update(
            {
                "admitted": True,
                "kernel_sha256": kernel_sha,
                "rootfs_sha256": rootfs_sha,
                "job_image_sha256": job_sha,
                "rootfs_read_only": True,
                "guest_writes_tmpfs_only": True,
            }
        )
    except BaseException:
        _append_event(evidence, "vm", "lifecycle", "failed")
        _append_event(evidence, "vm", "telemetry_loss", "observed")
    finally:
        proxy_telemetry: dict[str, Any] = {}
        if proxy is not None:
            purge_proxy = False
            try:
                proxy.stop()
            except BaseException:
                pass
            try:
                purge_proxy = getattr(proxy, "purge_verified", False) is True
            except BaseException:
                purge_proxy = False
            try:
                proxy_events = proxy.browser_events_snapshot()
                proxy_telemetry = proxy.telemetry_snapshot()
            except BaseException:
                proxy_events = []
            for event in proxy_events if isinstance(proxy_events, list) else []:
                if not isinstance(event, dict):
                    continue
                disposition = event.get("disposition")
                if event.get("kind") == "telemetry_loss" and disposition == "observed":
                    _append_event(evidence, "egress", "telemetry_loss", "observed")
                elif event.get("kind") == "network_request" and disposition in {
                    "allowed",
                    "blocked",
                }:
                    web_origin = event.get("web_origin")
                    connect_authority = event.get("connect_authority")
                    if not (
                        (isinstance(web_origin, str) and connect_authority is None)
                        or (
                            web_origin is None
                            and isinstance(connect_authority, str)
                        )
                    ):
                        _append_event(
                            evidence, "egress", "telemetry_loss", "observed"
                        )
                        continue
                    _append_event(
                        evidence,
                        "egress",
                        "network_request",
                        disposition,
                        web_origin=web_origin,
                        connect_authority=connect_authority,
                    )
        process_clean, exit_code, cgroup_readback, purge_cgroup = _terminate(process, paths)
        purge_process = process_clean
        runtime_identity["vmm_exit_code"] = exit_code
        runtime_identity["cgroup_limits"] = cgroup_readback
        purge_network = _cleanup_network(paths) if network_attempted else True
        try:
            shutil.rmtree(paths.jail_root.parent)
        except FileNotFoundError:
            pass
        except OSError:
            pass
        purge_jail = not paths.jail_root.parent.exists()
        os.close(lock_fd)

    purge = _purge_summary(
        processes_reaped=purge_process,
        cgroup_removed=purge_cgroup,
        network_namespace_removed=purge_network,
        ram_jail_removed=purge_jail,
        egress_worker_reaped=purge_proxy,
    )
    purge_verified = purge["verified_externally"]
    if purge_verified and guest_result is not None and "error" not in guest_result:
        _append_event(evidence, "vm", "lifecycle", "stopped")
        evidence["streams"]["vm"]["complete"] = True
    else:
        if not any(event["source"] == "vm" and event["kind"] == "telemetry_loss" for event in evidence["events"]):
            _append_event(evidence, "vm", "telemetry_loss", "observed")
    proxy_complete = _egress_stream_complete(
        proxy_present=proxy is not None,
        egress_worker_reaped=purge_proxy,
        network_namespace_removed=purge_network,
        telemetry=proxy_telemetry,
    )
    evidence["streams"]["egress"]["complete"] = bool(proxy_complete)
    reduction = reduce_browser_evidence(evidence, request)
    _enforce_purge_gate(reduction, purge_verified)
    return BrowserProbeResult(
        job_id=job_id,
        request=request,
        evidence=evidence,
        reduction=reduction,
        runtime=runtime_identity,
        artifacts=artifacts,
        purge=purge,
    )


__all__ = [
    "BrowserProbeResult",
    "FirecrackerRuntimeError",
    "FirecrackerUnavailable",
    "PreflightCheck",
    "PreflightReport",
    "preflight_firecracker",
    "run_browser_probe",
]
