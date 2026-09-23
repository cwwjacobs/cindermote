"""Compatibility API for the disabled portable Cindermote spine."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from mcp_guest_controller import portable_execution_denial


class CindermoteService:
    def __init__(self) -> None:
        self.detonations: Dict[str, Dict[str, Any]] = {}

    def create_detonation(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Deny portable detonation without constructing execution artifacts."""

        return portable_execution_denial()

    def get_detonation(self, detonation_id: str) -> Optional[Dict[str, Any]]:
        return self.detonations.get(detonation_id)

    def collapse_detonation(self, detonation_id: str, reason: str = "operator_burn") -> Optional[Dict[str, Any]]:
        return None
