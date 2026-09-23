"""Authority-free compatibility facade for the retired portable vertical spine.

CF-PORT-001 disables this path because it launched untrusted MCP targets in the
host orchestrator's namespace.  The class remains importable during migration,
but it cannot execute or attest a run.
"""

from __future__ import annotations

from typing import Any, Dict, List, NoReturn, Optional

from mcp_guest_controller import GuestMCPController, HostNativeExecutionDisabled


class CindermoteVerticalSpine:
    def __init__(self, run_id: str, mcp_target_cmd: List[str], signing_key: Optional[bytes] = None) -> None:
        self.run_id = run_id
        self.mcp_target_cmd = list(mcp_target_cmd)
        self.signing_key = signing_key
        self.guest_controller = GuestMCPController(run_id, mcp_target_cmd)
        self.events: List[Dict[str, Any]] = []

    def execute_vertical_run(self, trigger_collapse: bool = False) -> NoReturn:
        """Deny before target launch and emit no execution attestation."""

        raise HostNativeExecutionDisabled()
