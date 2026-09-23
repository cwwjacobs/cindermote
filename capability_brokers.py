"""Cindermote Capability Brokers.

Routes every consequential capability through declared typed brokers:
- mcp_tool_invocation
- guest_network
- filesystem_access
- process_spawning
- synthetic_secret_access
- evidence_submission
- model_provider_relay

Dispositions: ALLOW, DENY, QUARANTINE, COLLAPSE.
Unknown capability requests force COLLAPSE.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class BrokerDecision:
    capability_name: str
    disposition: str  # ALLOW, DENY, QUARANTINE, COLLAPSE
    collapse_cue: Optional[str] = None
    reason: str = ""


class CapabilityBroker:
    def __init__(self) -> None:
        self.declared_capabilities = {
            "mcp_tool_echo": "ALLOW",
            "mcp_tool_invocation": "ALLOW",
            "model_provider_relay": "ALLOW",
            "evidence_submission": "ALLOW",
            "synthetic_secret_access": "DENY",
            "guest_network": "DENY",
            "filesystem_access": "DENY",
            "process_spawning": "DENY",
            "host_path_access": "COLLAPSE",
            "real_secret_request": "COLLAPSE",
            "broker_bypass_attempt": "COLLAPSE",
        }

    def evaluate_request(self, capability_name: str, payload: Dict[str, Any]) -> BrokerDecision:
        """Evaluates a capability request against declared capability manifests."""
        # Check payload contents for deterministic collapse triggers
        payload_str = str(payload).lower()
        if "/etc/shadow" in payload_str or "host_path" in payload_str or "/etc/passwd" in payload_str:
            return BrokerDecision(
                capability_name=capability_name,
                disposition="COLLAPSE",
                collapse_cue="host_path_access",
                reason="Attempted unauthorized host filesystem path access.",
            )

        if capability_name not in self.declared_capabilities:
            # Unknown capability request -> COLLAPSE
            return BrokerDecision(
                capability_name=capability_name,
                disposition="COLLAPSE",
                collapse_cue="unknown_capability_request",
                reason=f"Undeclared capability requested: {capability_name}",
            )

        disp = self.declared_capabilities[capability_name]
        cue = "host_path_access" if disp == "COLLAPSE" else None
        return BrokerDecision(
            capability_name=capability_name,
            disposition=disp,
            collapse_cue=cue,
            reason=f"Policy disposition for {capability_name}: {disp}",
        )
