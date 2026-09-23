"""Cindermote agent-probe v0."""

from __future__ import annotations

from typing import Any


def run_agent_probe(*args: Any, **kwargs: Any) -> Any:
    from .runner import run_agent_probe as implementation

    return implementation(*args, **kwargs)


__all__ = ["run_agent_probe"]
