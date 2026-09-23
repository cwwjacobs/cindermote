"""Cindermote Collapse Mesh & Cue Router (Phase 5).

Defines deterministic triggers and actions for kernel collapse.
No ambiguous default; undeclared or violating actions force COLLAPSE or DENY.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class CollapseEvent:
    cue_id: str
    trigger_condition: str
    terminal_action: str  # ALLOW, DENY, QUARANTINE, COLLAPSE
    details: Dict[str, str]


class CollapseMesh:
    def __init__(self) -> None:
        self.cue_rules: Dict[str, str] = {
            "undeclared_destination": "COLLAPSE",
            "undeclared_tool": "DENY",
            "host_path_request": "COLLAPSE",
            "real_secret_request": "COLLAPSE",
            "privilege_escalation": "COLLAPSE",
            "broker_bypass_attempt": "COLLAPSE",
            "evidence_tampering": "COLLAPSE",
            "policy_mutation": "COLLAPSE",
            "unexpected_child_process": "COLLAPSE",
            "unexpected_listening_socket": "COLLAPSE",
            "raw_output_relay_attempt": "DENY",
            "cross_tenant_identifier": "COLLAPSE",
            "unknown_protocol_frame": "COLLAPSE",
            "telemetry_loss": "COLLAPSE",
            "watchdog_loss": "COLLAPSE",
        }

    def evaluate_event(self, cue_id: str, context: Dict[str, str]) -> CollapseEvent:
        action = self.cue_rules.get(cue_id, "COLLAPSE")  # Fail-closed default
        return CollapseEvent(
            cue_id=cue_id,
            trigger_condition=context.get("trigger", "unspecified"),
            terminal_action=action,
            details=context,
        )
