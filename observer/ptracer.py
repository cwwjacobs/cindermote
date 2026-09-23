"""Linux x86_64 ptrace observer and pre-exec seccomp-BPF filter.

The tracee never attests to containment. The host observer derives telemetry
from syscall stops, while the seccomp program independently denies the most
dangerous syscall classes.
"""

from __future__ import annotations

import ctypes
import errno
import os
import platform
import signal
import socket
import struct
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from cindermote.observer.detectors import (
    DetectorEngine,
    bounded_subject,
    classify_path,
    make_event,
)


libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.restype = ctypes.c_long

# ptrace requests and options (Linux UAPI)
PTRACE_TRACEME = 0
PTRACE_PEEKDATA = 2
PTRACE_ATTACH = 16
PTRACE_SYSCALL = 24
PTRACE_SETOPTIONS = 0x4200
PTRACE_GETEVENTMSG = 0x4201
PTRACE_GETREGS = 12
PTRACE_O_TRACESYSGOOD = 0x00000001
PTRACE_O_TRACEFORK = 0x00000002
PTRACE_O_TRACEVFORK = 0x00000004
PTRACE_O_TRACECLONE = 0x00000008
PTRACE_O_TRACEEXEC = 0x00000010
PTRACE_O_EXITKILL = 0x00100000
PTRACE_EVENT_FORK = 1
PTRACE_EVENT_VFORK = 2
PTRACE_EVENT_CLONE = 3
PTRACE_EVENT_EXEC = 4
WAIT_WALL = 0x40000000

# prctl/seccomp UAPI
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_TRAP = 0x00030000
SECCOMP_RET_ALLOW = 0x7FFF0000
AUDIT_ARCH_X86_64 = 0xC000003E

# classic BPF opcodes
BPF_LD_W_ABS = 0x20
BPF_JMP_JEQ_K = 0x15
BPF_JMP_JSET_K = 0x45
BPF_RET_K = 0x06

# x86_64 syscall numbers used by the policy/observer
SYS_READ = 0
SYS_WRITE = 1
SYS_IOCTL = 16
SYS_SOCKET = 41
SYS_CONNECT = 42
SYS_CLONE = 56
SYS_FORK = 57
SYS_VFORK = 58
SYS_EXECVE = 59
SYS_PTRACE = 101
SYS_PIVOT_ROOT = 155
SYS_MOUNT = 165
SYS_UMOUNT2 = 166
SYS_CLOCK_GETTIME = 228
SYS_OPENAT = 257
SYS_UNSHARE = 272
SYS_SETNS = 308
SYS_EXECVEAT = 322
SYS_CLONE3 = 435

SIOCGIFCONF = 0x8912
CLONE_NAMESPACE_MASK = (
    0x00020000  # CLONE_NEWNS
    | 0x04000000  # CLONE_NEWUTS
    | 0x08000000  # CLONE_NEWIPC
    | 0x10000000  # CLONE_NEWUSER
    | 0x20000000  # CLONE_NEWPID
    | 0x40000000  # CLONE_NEWNET
    | 0x02000000  # CLONE_NEWCGROUP
)

SYSCALL_NAMES = {
    SYS_READ: "read",
    SYS_WRITE: "write",
    SYS_IOCTL: "ioctl",
    SYS_SOCKET: "socket",
    SYS_CONNECT: "connect",
    SYS_CLONE: "clone",
    SYS_FORK: "fork",
    SYS_VFORK: "vfork",
    SYS_EXECVE: "execve",
    SYS_PTRACE: "ptrace",
    SYS_PIVOT_ROOT: "pivot_root",
    SYS_MOUNT: "mount",
    SYS_UMOUNT2: "umount2",
    SYS_CLOCK_GETTIME: "clock_gettime",
    SYS_OPENAT: "openat",
    SYS_UNSHARE: "unshare",
    SYS_SETNS: "setns",
    SYS_EXECVEAT: "execveat",
    SYS_CLONE3: "clone3",
}


class SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter))]


class UserRegsStruct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]


def _stmt(code: int, k: int) -> tuple[int, int, int, int]:
    return code, 0, 0, k


def _jump(code: int, k: int, jt: int, jf: int) -> tuple[int, int, int, int]:
    return code, jt, jf, k


def seccomp_instructions() -> list[tuple[int, int, int, int]]:
    """Build the deterministic v1.1 syscall filter."""
    instructions: list[tuple[int, int, int, int]] = [
        _stmt(BPF_LD_W_ABS, 4),
        _jump(BPF_JMP_JEQ_K, AUDIT_ARCH_X86_64, 1, 0),
        _stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
        _stmt(BPF_LD_W_ABS, 0),
    ]

    # socket(domain, ...): trap Internet and packet families; AF_UNIX remains
    # available for the interpreter runtime.
    instructions.extend(
        [
            _jump(BPF_JMP_JEQ_K, SYS_SOCKET, 0, 8),
            _stmt(BPF_LD_W_ABS, 16),
            _jump(BPF_JMP_JEQ_K, socket.AF_INET, 0, 1),
            _stmt(BPF_RET_K, SECCOMP_RET_TRAP),
            _jump(BPF_JMP_JEQ_K, socket.AF_INET6, 0, 1),
            _stmt(BPF_RET_K, SECCOMP_RET_TRAP),
            _jump(BPF_JMP_JEQ_K, socket.AF_PACKET, 0, 1),
            _stmt(BPF_RET_K, SECCOMP_RET_TRAP),
            _stmt(BPF_LD_W_ABS, 0),
        ]
    )

    # ioctl(fd, SIOCGIFCONF, ...)
    instructions.extend(
        [
            _jump(BPF_JMP_JEQ_K, SYS_IOCTL, 0, 3),
            _stmt(BPF_LD_W_ABS, 16 + 8),
            _jump(BPF_JMP_JEQ_K, SIOCGIFCONF, 0, 1),
            _stmt(BPF_RET_K, SECCOMP_RET_TRAP),
            _stmt(BPF_LD_W_ABS, 0),
        ]
    )

    # clone() is allowed only when no namespace bit is requested.
    instructions.extend(
        [
            _jump(BPF_JMP_JEQ_K, SYS_CLONE, 0, 3),
            _stmt(BPF_LD_W_ABS, 16),
            _jump(BPF_JMP_JSET_K, CLONE_NAMESPACE_MASK, 0, 1),
            _stmt(BPF_RET_K, SECCOMP_RET_TRAP),
            _stmt(BPF_LD_W_ABS, 0),
        ]
    )

    for syscall_number in (
        SYS_MOUNT,
        SYS_UMOUNT2,
        SYS_PIVOT_ROOT,
        SYS_SETNS,
        SYS_UNSHARE,
        SYS_PTRACE,
        SYS_CLONE3,
    ):
        instructions.extend(
            [
                _jump(BPF_JMP_JEQ_K, syscall_number, 0, 1),
                _stmt(BPF_RET_K, SECCOMP_RET_TRAP),
            ]
        )
    instructions.append(_stmt(BPF_RET_K, SECCOMP_RET_ALLOW))
    return instructions


def seccomp_blob() -> bytes:
    return b"".join(struct.pack("=HBBI", *item) for item in seccomp_instructions())


def write_seccomp_blob(path: str | Path) -> None:
    Path(path).write_bytes(seccomp_blob())


def install_seccomp() -> None:
    if platform.machine() not in {"x86_64", "amd64"}:
        raise OSError(errno.ENOTSUP, "Cindermote seccomp policy supports x86_64 only")
    raw = seccomp_instructions()
    filters = (SockFilter * len(raw))(*(SockFilter(*item) for item in raw))
    program = SockFprog(len=len(raw), filter=filters)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(program)) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def request_tracing() -> None:
    if libc.ptrace(PTRACE_TRACEME, 0, None, None) == -1:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _ptrace(request: int, pid: int, address: int = 0, data: int = 0) -> int:
    ctypes.set_errno(0)
    result = libc.ptrace(
        ctypes.c_uint(request),
        ctypes.c_uint(pid),
        ctypes.c_void_p(address),
        ctypes.c_void_p(data),
    )
    error = ctypes.get_errno()
    if result == -1 and error:
        raise OSError(error, os.strerror(error))
    return int(result)


def _getregs(pid: int) -> UserRegsStruct:
    registers = UserRegsStruct()
    result = libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
    if result == -1:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return registers


def _peek(pid: int, address: int) -> bytes:
    ctypes.set_errno(0)
    word = libc.ptrace(PTRACE_PEEKDATA, pid, ctypes.c_void_p(address), None)
    error = ctypes.get_errno()
    if word == -1 and error:
        raise OSError(error, os.strerror(error))
    mask = (1 << (ctypes.sizeof(ctypes.c_long) * 8)) - 1
    return int(word & mask).to_bytes(ctypes.sizeof(ctypes.c_long), "little")


def read_tracee_bytes(pid: int, address: int, maximum: int) -> bytes:
    result = bytearray()
    while len(result) < maximum:
        try:
            chunk = _peek(pid, address + len(result))
        except OSError:
            break
        result.extend(chunk)
        if b"\x00" in chunk:
            break
    return bytes(result[:maximum])


def read_tracee_string(pid: int, address: int, maximum: int = 4096) -> str:
    if not address:
        return ""
    raw = read_tracee_bytes(pid, address, maximum)
    return raw.split(b"\x00", 1)[0].decode("utf-8", "surrogateescape")


def read_sockaddr(pid: int, address: int, length: int) -> str:
    raw = read_tracee_bytes(pid, address, min(max(length, 0), 128))
    if len(raw) < 2:
        return "unknown:*"
    family = int.from_bytes(raw[:2], "little")
    if family == socket.AF_INET and len(raw) >= 8:
        port = int.from_bytes(raw[2:4], "big")
        host = socket.inet_ntop(socket.AF_INET, raw[4:8])
        return f"{host}:{port}"
    if family == socket.AF_INET6 and len(raw) >= 24:
        port = int.from_bytes(raw[2:4], "big")
        host = socket.inet_ntop(socket.AF_INET6, raw[8:24])
        return f"[{host}]:{port}"
    return f"family-{family}:*"


@dataclass
class HostTracer:
    root_pid: int
    detector: DetectorEngine
    exec_depth_limit: int = 3
    timing_limit: int = 100
    start_monotonic: float = field(default_factory=time.monotonic)
    active_pids: set[int] = field(default_factory=set)
    in_syscall: dict[int, bool] = field(default_factory=dict)
    last_syscall: dict[int, int] = field(default_factory=dict)
    parent_by_pid: dict[int, int] = field(default_factory=dict)
    counters: Counter = field(default_factory=Counter)
    clock_calls: dict[int, list[float]] = field(default_factory=lambda: defaultdict(list))
    max_rss_kib: int = 0
    seccomp_violation: bool = False
    namespace_escape: bool = False
    trace_error: str | None = None
    exit_codes: dict[int, int] = field(default_factory=dict)

    @staticmethod
    def _options() -> int:
        return (
            PTRACE_O_TRACESYSGOOD
            | PTRACE_O_TRACEFORK
            | PTRACE_O_TRACEVFORK
            | PTRACE_O_TRACECLONE
            | PTRACE_O_TRACEEXEC
            | PTRACE_O_EXITKILL
        )

    def _register_root(self) -> None:
        self.active_pids.add(self.root_pid)
        self.in_syscall[self.root_pid] = False

    def begin(self) -> None:
        """Begin tracing a child that used PTRACE_TRACEME."""

        _ptrace(PTRACE_SETOPTIONS, self.root_pid, 0, self._options())
        self._register_root()
        self.resume_root()

    def attach(self) -> None:
        """Attach to a host-validated stopped descendant without resuming it."""

        _ptrace(PTRACE_ATTACH, self.root_pid, 0, 0)
        deadline = time.monotonic() + 2.0
        while True:
            try:
                waited_pid, status = os.waitpid(
                    self.root_pid,
                    os.WNOHANG | WAIT_WALL,
                )
            except ChildProcessError as exc:
                raise OSError(errno.ECHILD, os.strerror(errno.ECHILD)) from exc
            if waited_pid == self.root_pid:
                if not os.WIFSTOPPED(status):
                    raise OSError(errno.ESRCH, os.strerror(errno.ESRCH))
                break
            if time.monotonic() >= deadline:
                raise OSError(errno.ETIMEDOUT, os.strerror(errno.ETIMEDOUT))
            time.sleep(0.005)
        _ptrace(PTRACE_SETOPTIONS, self.root_pid, 0, self._options())
        self._register_root()

    def resume_root(self) -> None:
        if self.root_pid not in self.active_pids:
            raise OSError(errno.ESRCH, os.strerror(errno.ESRCH))
        _ptrace(PTRACE_SYSCALL, self.root_pid, 0, 0)

    def _depth(self, pid: int) -> int:
        depth = 0
        seen = set()
        while pid in self.parent_by_pid and pid not in seen:
            seen.add(pid)
            pid = self.parent_by_pid[pid]
            depth += 1
        return depth

    def _record_namespace_escape(self, syscall_number: int) -> None:
        self.namespace_escape = True
        self.detector.record(
            make_event(
                "syscall",
                "namespace_escape_attempt",
                SYSCALL_NAMES.get(syscall_number, f"syscall-{syscall_number}"),
                "exec",
                "known_bad",
            )
        )

    def _on_syscall_entry(self, pid: int, registers: UserRegsStruct) -> None:
        syscall_number = int(registers.orig_rax)
        self.last_syscall[pid] = syscall_number
        self.counters["syscall_events"] += 1

        if syscall_number == SYS_OPENAT:
            path = read_tracee_string(pid, int(registers.rsi))
            flags = int(registers.rdx)
            path_events, canary = classify_path(path, flags)
            for event in path_events:
                self.detector.record(event)
            if canary:
                self.detector.trip_canary(canary)
            if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC):
                self.counters["fs_mutations"] += 1
            if path == "/dev/kvm":
                self._record_namespace_escape(syscall_number)

        elif syscall_number == SYS_SOCKET:
            domain = int(registers.rdi)
            if domain in {socket.AF_INET, socket.AF_INET6, socket.AF_PACKET}:
                family = {
                    socket.AF_INET: "AF_INET:*",
                    socket.AF_INET6: "AF_INET6:*",
                    socket.AF_PACKET: "AF_PACKET:*",
                }[domain]
                self.detector.record(
                    make_event(
                        "net",
                        "network_exfil_attempt",
                        family,
                        "connect",
                        "known_bad",
                    )
                )
                self.detector.add_destination(family, "blocked-by-seccomp")

        elif syscall_number == SYS_CONNECT:
            destination = read_sockaddr(pid, int(registers.rsi), int(registers.rdx))
            self.detector.add_destination(destination, "recorded+denied")
            self.detector.record(
                make_event(
                    "net",
                    "network_exfil_attempt",
                    bounded_subject(destination),
                    "connect",
                    "known_bad",
                )
            )

        elif syscall_number in {SYS_CLONE, SYS_FORK, SYS_VFORK}:
            self.counters["forks"] += 1
            if syscall_number == SYS_CLONE and int(registers.rdi) & CLONE_NAMESPACE_MASK:
                self._record_namespace_escape(syscall_number)
            if self._depth(pid) + 1 > self.exec_depth_limit and time.monotonic() - self.start_monotonic <= 5:
                self.detector.record(
                    make_event(
                        "proc",
                        "exec_spawn_chain",
                        "process_depth_exceeded",
                        "fork",
                        "anomalous",
                    )
                )

        elif syscall_number in {SYS_EXECVE, SYS_EXECVEAT}:
            self.counters["exec_spawns"] += 1
            self.detector.record(
                make_event("proc", "process_exec", "sandbox_exec", "exec", "baseline")
            )

        elif syscall_number == SYS_CLOCK_GETTIME:
            now = time.monotonic()
            calls = self.clock_calls[pid]
            calls.append(now)
            while calls and calls[0] < now - 1.0:
                calls.pop(0)
            if len(calls) > self.timing_limit:
                self.detector.record(
                    make_event(
                        "syscall",
                        "timing_evasion",
                        "clock_gettime_rate",
                        "read",
                        "anomalous",
                    )
                )

        elif syscall_number in {
            SYS_SETNS,
            SYS_UNSHARE,
            SYS_MOUNT,
            SYS_UMOUNT2,
            SYS_PIVOT_ROOT,
            SYS_PTRACE,
            SYS_CLONE3,
        }:
            self._record_namespace_escape(syscall_number)

    def sample_resources(self) -> None:
        for pid in tuple(self.active_pids):
            try:
                data = Path(f"/proc/{pid}/status").read_text(encoding="utf-8", errors="replace")
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
            for line in data.splitlines():
                if line.startswith("VmRSS:"):
                    try:
                        self.max_rss_kib = max(self.max_rss_kib, int(line.split()[1]))
                    except (IndexError, ValueError):
                        pass
                    break

    def process_wait_status(self, pid: int, status: int) -> None:
        if os.WIFEXITED(status):
            self.exit_codes[pid] = os.WEXITSTATUS(status)
            self.active_pids.discard(pid)
            return
        if os.WIFSIGNALED(status):
            self.exit_codes[pid] = 128 + os.WTERMSIG(status)
            self.active_pids.discard(pid)
            return
        if not os.WIFSTOPPED(status):
            return

        stop_signal = os.WSTOPSIG(status)
        event = status >> 16
        try:
            if event in {PTRACE_EVENT_FORK, PTRACE_EVENT_VFORK, PTRACE_EVENT_CLONE}:
                child = ctypes.c_ulonglong()
                result = libc.ptrace(PTRACE_GETEVENTMSG, pid, None, ctypes.byref(child))
                if result == -1:
                    error = ctypes.get_errno()
                    raise OSError(error, os.strerror(error))
                child_pid = int(child.value)
                self.active_pids.add(child_pid)
                self.parent_by_pid[child_pid] = pid
                self.in_syscall[child_pid] = False
                _ptrace(PTRACE_SYSCALL, pid, 0, 0)
                return

            if stop_signal == (signal.SIGTRAP | 0x80):
                registers = _getregs(pid)
                entering = not self.in_syscall.get(pid, False)
                self.in_syscall[pid] = entering
                if entering:
                    self._on_syscall_entry(pid, registers)
                _ptrace(PTRACE_SYSCALL, pid, 0, 0)
                return

            if stop_signal == signal.SIGSYS:
                self.seccomp_violation = True
                syscall_number = self.last_syscall.get(pid)
                if syscall_number in {
                    SYS_SETNS,
                    SYS_UNSHARE,
                    SYS_MOUNT,
                    SYS_UMOUNT2,
                    SYS_PIVOT_ROOT,
                    SYS_PTRACE,
                    SYS_CLONE3,
                }:
                    self._record_namespace_escape(syscall_number)
                _ptrace(PTRACE_SYSCALL, pid, 0, signal.SIGSYS)
                return

            # Exec and child-attach SIGTRAP/SIGSTOP stops are bookkeeping only.
            deliver = 0 if stop_signal in {signal.SIGTRAP, signal.SIGSTOP, signal.SIGCHLD} else stop_signal
            _ptrace(PTRACE_SYSCALL, pid, 0, deliver)
        except (OSError, ProcessLookupError) as exc:
            if getattr(exc, "errno", None) not in {errno.ESRCH, errno.ECHILD}:
                self.trace_error = f"{type(exc).__name__}:{getattr(exc, 'errno', 'unknown')}"

    def telemetry_summary(self) -> dict:
        return {
            "syscall_events": int(self.counters["syscall_events"]),
            "fs_mutations": int(self.counters["fs_mutations"]),
            "dns_attempts": int(self.counters["dns_attempts"]),
            "exec_spawns": int(self.counters["exec_spawns"]),
            "source": "ptrace + seccomp (read-only, host side)",
        }
