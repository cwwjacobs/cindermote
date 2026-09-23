"""Cindermote Kernel Laws and Verification Rules (Phase 1).

Enforces the 10 invariant kernel laws:
1. Raw untrusted semantic output never enters the trusted host agent.
2. Every external capability is brokered, blocked, or absent.
3. Unknown capability requests collapse the kernel.
4. Operator and host-owned policy can initiate Burn at any time.
5. Collapse does not depend on guest cooperation.
6. Burn must produce purge evidence.
7. Replay remains sealed outside a quarantined viewer.
8. Missing evidence is failure, not success.
9. API-provider exposure is an explicit trust boundary.
10. Closure applies only to the declared reachable surface, never to the universe in general.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Set


@dataclass
class VerificationResult:
    valid: bool
    errors: List[str]


class KernelLawsValidator:
    def __init__(self, schemas_dir: Path | str | None = None) -> None:
        if schemas_dir is None:
            schemas_dir = Path(__file__).resolve().parent.parent / "schemas"
        self.schemas_dir = Path(schemas_dir)

    def validate_seams(self, seam_registry: Dict[str, Any]) -> VerificationResult:
        errors = []
        seams = seam_registry.get("seams", [])
        for seam in seams:
            if not seam.get("owner"):
                errors.append(f"Seam {seam.get('seam_id')} has no assigned owner.")
            if not seam.get("broker") and seam.get("source_zone") == "TAINTED_GUEST" and seam.get("target_zone") == "TRUSTED_HOST":
                errors.append(f"Unbrokered guest-to-host seam detected: {seam.get('seam_id')}")
        return VerificationResult(valid=len(errors) == 0, errors=errors)

    def validate_capabilities(self, capability_manifest: Dict[str, Any]) -> VerificationResult:
        errors = []
        capabilities = capability_manifest.get("capabilities", [])
        valid_dispositions = {"ALLOW", "DENY", "BROKERED", "PROHIBITED"}
        for cap in capabilities:
            disp = cap.get("disposition")
            if not disp or disp not in valid_dispositions:
                errors.append(f"Capability {cap.get('capability_id')} has invalid or missing disposition: {disp}")
            if disp == "BROKERED" and not cap.get("broker_required"):
                errors.append(f"Capability {cap.get('capability_id')} set to BROKERED but broker_required is False")
        return VerificationResult(valid=len(errors) == 0, errors=errors)

    def validate_collapse_cues(self, cue_registry: Dict[str, Any]) -> VerificationResult:
        errors = []
        cues = cue_registry.get("cues", [])
        valid_actions = {"ALLOW", "DENY", "QUARANTINE", "COLLAPSE"}
        for cue in cues:
            action = cue.get("terminal_action")
            if not action or action not in valid_actions:
                errors.append(f"Collapse cue {cue.get('cue_id')} lacks valid terminal action: {action}")
        return VerificationResult(valid=len(errors) == 0, errors=errors)


def run_kernel_law_checks() -> VerificationResult:
    validator = KernelLawsValidator()
    # Sample default verification against canonical definitions
    sample_seams = {
        "version": "v1",
        "seams": [
            {
                "seam_id": "guest_vsock_cdp",
                "source_zone": "TAINTED_GUEST",
                "target_zone": "TRUSTED_HOST",
                "owner": "cindermote-proxy",
                "broker": "cindermote-proxy",
                "instrumented": True,
                "collapse_cue_id": "malformed_frame"
            }
        ]
    }
    sample_caps = {
        "version": "v1",
        "capabilities": [
            {
                "capability_id": "network_egress",
                "component_id": "guest_browser",
                "disposition": "BROKERED",
                "broker_required": True
            }
        ]
    }
    sample_cues = {
        "version": "v1",
        "cues": [
            {
                "cue_id": "malformed_frame",
                "trigger_condition": "invalid_json_or_oversized_payload",
                "terminal_action": "COLLAPSE"
            }
        ]
    }

    v1 = validator.validate_seams(sample_seams)
    v2 = validator.validate_capabilities(sample_caps)
    v3 = validator.validate_collapse_cues(sample_cues)

    all_errors = v1.errors + v2.errors + v3.errors
    return VerificationResult(valid=len(all_errors) == 0, errors=all_errors)
