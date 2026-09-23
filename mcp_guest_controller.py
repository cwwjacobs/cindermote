"""Authority-free compatibility surface for the retired portable MCP controller.

The historical implementation launched an attacker-influenced command directly
in the host orchestrator's namespace.  CF-PORT-001 permanently removes that
execution authority.  Protocol-facing methods remain importable for callers
that still need to migrate, but every attempted use fails closed.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, NoReturn, Optional


HOST_NATIVE_EXECUTION_DISABLED = "HOST_NATIVE_EXECUTION_DISABLED"
HOST_NATIVE_EXECUTION_DISABLED_MESSAGE = (
    "Portable host-native execution is disabled; this path cannot execute "
    "untrusted targets. An admitted Firecracker runtime is required."
)


class HostNativeExecutionDisabled(RuntimeError):
    """Stable fail-closed error for every retired portable execution attempt."""

    reason_code = HOST_NATIVE_EXECUTION_DISABLED
    execution_started = False

    def __init__(self) -> None:
        super().__init__(HOST_NATIVE_EXECUTION_DISABLED_MESSAGE)

    def to_result(self) -> Dict[str, Any]:
        return {
            "status": "DENIED",
            "disposition": "DENY",
            "reason_code": self.reason_code,
            "message": str(self),
            "execution_started": self.execution_started,
            "required_runtime": "FIRECRACKER",
            "runtime_admission_required": True,
        }


def portable_execution_denial() -> Dict[str, Any]:
    """Return the compatibility API's non-attesting denial payload."""

    return HostNativeExecutionDisabled().to_result()


def _deny_portable_execution() -> NoReturn:
    raise HostNativeExecutionDisabled()


@dataclass
class BoundedHostEvent:
    event_version: str = "cindermote-event/v1"
    run_id: str = ""
    event_type: str = ""
    timestamp_utc: str = ""
    tool_count: int = 0
    prompt_count: int = 0
    resource_count: int = 0
    surface_hashes: Dict[str, Any] = field(default_factory=dict)
    capability_classification: str = ""
    collapse_cue: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.timestamp_utc:
            self.timestamp_utc = dt.datetime.now(dt.timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.collapse_cue is None:
            d.pop("collapse_cue", None)
        return d


class GuestMCPController:
    def __init__(self, run_id: str, command: List[str]) -> None:
        self.run_id = run_id
        self.command = list(command)
        self.proc: None = None
        self.msg_id = 0
        self.discovered_tools: List[Dict[str, Any]] = []
        self.tool_schema_hashes: List[str] = []

    def start_target(self) -> NoReturn:
        """Deny the retired host-native target launch before process creation."""

        _deny_portable_execution()

    def send_request(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> NoReturn:
        _deny_portable_execution()

    def send_notification(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> NoReturn:
        _deny_portable_execution()

    def initialize(self) -> NoReturn:
        _deny_portable_execution()

    def discover_tools(self) -> NoReturn:
        _deny_portable_execution()

    def invoke_tool(self, name: str, arguments: Dict[str, Any]) -> NoReturn:
        _deny_portable_execution()

    def stop(self) -> None:
        """Compatibility no-op: this controller can no longer start a process."""

        self.proc = None
