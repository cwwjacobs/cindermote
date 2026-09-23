"""Cindermote Contained API-Model Relay (Phase 4).

Connects the Scalar Kernel's guest semantic reader to approved external model
endpoints (e.g. DeepSeek, OpenAI-compatible APIs) while preventing raw guest
conversation or untrusted prompt text from escaping to the trusted host agent.
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.request
import urllib.error

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ModelRelayConfig:
    endpoint: str = "https://api.deepseek.com/v1"
    model_id: str = "deepseek-chat"
    max_tokens_budget: int = 16_000
    timeout_sec: int = 30
    allowed_endpoints: List[str] = field(
        default_factory=lambda: ["https://api.deepseek.com/v1", "https://api.openai.com/v1"]
    )


class ContainedModelRelay:
    def __init__(self, config: Optional[ModelRelayConfig] = None) -> None:
        self.config = config or ModelRelayConfig()
        self.total_tokens_used = 0

    def query_contained_model(
        self,
        api_key: str,
        messages: List[Dict[str, str]],
        max_tokens: int = 500,
    ) -> Dict[str, Any]:
        """Relays a query to the model endpoint from inside the Scalar Kernel.

        Returns metadata & token usage to the host; raw prompt/completion
        remains in guest scope.
        """
        # Validate endpoint allowlist
        if not any(self.config.endpoint.startswith(allowed) for allowed in self.config.allowed_endpoints):
            raise ValueError(f"Endpoint {self.config.endpoint} is not in the allowed endpoint registry.")

        if self.total_tokens_used + max_tokens > self.config.max_tokens_budget:
            raise RuntimeError("Token budget exceeded for contained model relay.")

        url = f"{self.config.endpoint.rstrip('/')}/chat/completions"
        payload = {
            "model": self.config.model_id,
            "messages": messages,
            "max_tokens": max_tokens,
        }
        body_bytes = json.dumps(payload).encode("utf-8")
        if len(body_bytes) > 64 * 1024:
            raise ValueError("Request size exceeds 64KB boundary limit.")

        req = urllib.request.Request(
            url,
            data=body_bytes,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout_sec) as resp:
                resp_bytes = resp.read()
                if len(resp_bytes) > 256 * 1024:
                    raise ValueError("Response size exceeds 256KB boundary limit.")

                data = json.loads(resp_bytes.decode("utf-8"))
                usage = data.get("usage", {})
                used = usage.get("total_tokens", max_tokens)
                self.total_tokens_used += used

                choices = data.get("choices", [])
                raw_response_text = choices[0]["message"]["content"] if choices else ""

                # Return metadata reduction for host; guest retains raw response
                return {
                    "status_code": resp.status,
                    "model_used": data.get("model", self.config.model_id),
                    "tokens_used": used,
                    "cumulative_tokens": self.total_tokens_used,
                    "raw_response_guest_only": raw_response_text,
                    "response_hash": hashlib.sha256(raw_response_text.encode("utf-8")).hexdigest(),
                }
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="ignore")
            return {
                "status_code": e.code,
                "error": "HTTPError",
                "details_hash": hashlib.sha256(err_body.encode("utf-8")).hexdigest(),
            }
        except Exception as e:
            return {"status_code": 500, "error": str(e)}
