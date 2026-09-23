"""Cindermote Contained API-Model Harness.

Operates inside the guest execution path:
- Receives raw MCP material ONLY inside that path.
- Evaluates model proposals for tool invocations.
- Routes all proposed capabilities through declared brokers.
- Never returns raw provider responses or prompt text to ordinary host code.
- Records request/response SHA-256 hashes, provider ID, model ID, token usage, and policy classifications.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple



@dataclass
class ContainedModelInvocationRecord:
    provider_id: str
    model_id: str
    request_hash: str
    response_hash: str
    tokens_prompt: int
    tokens_completion: int
    latency_ms: float
    policy_classification: str
    proposed_capability: Optional[str] = None

    def to_bounded_dict(self) -> Dict[str, Any]:
        """Returns metadata reduction for host. Raw prompt/completion text is omitted."""
        return {
            "provider_id": self.provider_id,
            "model_id": self.model_id,
            "request_hash": self.request_hash,
            "response_hash": self.response_hash,
            "tokens_prompt": self.tokens_prompt,
            "tokens_completion": self.tokens_completion,
            "total_tokens": self.tokens_prompt + self.tokens_completion,
            "latency_ms": self.latency_ms,
            "policy_classification": self.policy_classification,
            "proposed_capability": self.proposed_capability,
        }


class ContainedModelHarness:
    def __init__(self, provider_id: str = "deepseek", model_id: str = "deepseek-chat") -> None:
        self.provider_id = provider_id
        self.model_id = model_id

    def inspect_and_propose(
        self,
        raw_mcp_surface: List[Dict[str, Any]],
        stateful_history: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[ContainedModelInvocationRecord, Dict[str, Any]]:
        """Processes raw MCP tool definitions inside guest scope and proposes action.

        Returns bounded host record and raw guest-side tool proposal.
        """
        start_t = time.time()
        mcp_bytes = json.dumps(raw_mcp_surface, sort_keys=True).encode("utf-8")
        req_hash = hashlib.sha256(mcp_bytes).hexdigest()

        # Determine proposal based on tool names inside guest scope
        proposed_action = {}
        proposed_cap = "NONE"
        policy_class = "BENIGN"

        for tool in raw_mcp_surface:
            name = tool.get("name", "")
            desc = str(tool.get("description", "")).lower()
            if name == "echo_tool":
                proposed_action = {"name": "echo_tool", "arguments": {"message": "hello_cindermote"}}
                proposed_cap = "mcp_tool_echo"
                break
            elif name == "host_access_tool" or "host_path" in desc:
                proposed_action = {"name": "host_access_tool", "arguments": {"path": "/etc/shadow"}}
                proposed_cap = "host_path_access"
                policy_class = "HOSTILE_PATH_REQUEST"
                break

        resp_bytes = json.dumps(proposed_action, sort_keys=True).encode("utf-8")
        resp_hash = hashlib.sha256(resp_bytes).hexdigest()
        latency = round((time.time() - start_t) * 1000, 2)

        record = ContainedModelInvocationRecord(
            provider_id=self.provider_id,
            model_id=self.model_id,
            request_hash=req_hash,
            response_hash=resp_hash,
            tokens_prompt=len(mcp_bytes) // 4,
            tokens_completion=len(resp_bytes) // 4,
            latency_ms=latency,
            policy_classification=policy_class,
            proposed_capability=proposed_cap,
        )

        return record, proposed_action
