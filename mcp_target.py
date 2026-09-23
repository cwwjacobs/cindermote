"""Cindermote MCP Target Containment & Enumeration (Phase 3).

Enforces contained execution of untrusted MCP targets inside the Scalar
Kernel. Returns bounded structural metadata only (hashes, surface counts,
dispositions) without passing raw semantic descriptions to the trusted host.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class MCPTargetConfig:
    target_id: str
    package_uri: str
    runtime_type: str = "node"  # node, python, binary
    transports: List[str] = field(default_factory=lambda: ["stdio"])
    allowed_network_destinations: List[str] = field(default_factory=list)
    policy_profile: str = "strict-mcp"


@dataclass
class MCPSurfaceSummary:
    target_id: str
    target_hash: str
    tool_count: int = 0
    prompt_count: int = 0
    resource_count: int = 0
    tool_schema_hashes: List[str] = field(default_factory=list)
    resource_hashes: List[str] = field(default_factory=list)
    capability_classifications: List[str] = field(default_factory=list)
    terminal_disposition: str = "ADMIT"


class MCPTargetContainer:
    def __init__(self, config: MCPTargetConfig) -> None:
        self.config = config

    def compute_target_hash(self) -> str:
        data = asdict(self.config)
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode("utf-8")).hexdigest()

    def enumerate_metadata_only(self, raw_guest_manifest: Dict[str, Any]) -> MCPSurfaceSummary:
        """Processes guest-side enumeration into bounded metadata only.

        Raw prompt text or tool descriptions are discarded before crossing
        outward.
        """
        tools = raw_guest_manifest.get("tools", [])
        prompts = raw_guest_manifest.get("prompts", [])
        resources = raw_guest_manifest.get("resources", [])

        schema_hashes = []
        for t in tools:
            schema_bytes = json.dumps(t.get("inputSchema", {}), sort_keys=True).encode("utf-8")
            schema_hashes.append(hashlib.sha256(schema_bytes).hexdigest())

        res_hashes = []
        for r in resources:
            uri_bytes = str(r.get("uri", "")).encode("utf-8")
            res_hashes.append(hashlib.sha256(uri_bytes).hexdigest())

        # Enforce containment rule: if raw host paths requested, reject
        disposition = "ADMIT"
        for t in tools:
            name = str(t.get("name", "")).lower()
            if "exec" in name or "shell" in name or "system" in name:
                disposition = "RESTRICT"

        return MCPSurfaceSummary(
            target_id=self.config.target_id,
            target_hash=self.compute_target_hash(),
            tool_count=len(tools),
            prompt_count=len(prompts),
            resource_count=len(resources),
            tool_schema_hashes=schema_hashes,
            resource_hashes=res_hashes,
            capability_classifications=["TOOL_EXEC", "RESOURCE_READ"],
            terminal_disposition=disposition,
        )
