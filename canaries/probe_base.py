"""Abstract base class for Cindermote detonation probes.

Every probe module under ``canaries/`` must define exactly one subclass of
``ProbeBase``.  The incident gate discovers and runs these probes through a
uniform lifecycle: ``setup() → execute() → teardown()``.

Probes declare their *expected* sandbox behaviour so that the gate can verify
containment held without relying on guest self-reports.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ProbeExpectation:
    """What the sandbox should do when this probe detonates."""

    risk: str  # "hostile" or "suspicious"
    decision: str  # "DENY" or "ALLOW"
    rules: frozenset[str] = field(default_factory=frozenset)  # detector rule_ids that should fire


class ProbeBase(abc.ABC):
    """Lifecycle contract for a single containment probe.

    Subclasses **must** implement:
        - ``name``       → unique snake_case identifier
        - ``description`` → human-readable one-liner
        - ``source``     → the Python source code of the hostile payload
        - ``expectation`` → what the sandbox should report

    Subclasses **may** override:
        - ``setup()``    → pre-detonation preparation (default: no-op)
        - ``teardown()`` → post-detonation cleanup (default: no-op)
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Unique snake_case identifier for this probe."""
        ...

    @property
    @abc.abstractmethod
    def description(self) -> str:
        """Human-readable one-line description."""
        ...

    @property
    @abc.abstractmethod
    def source(self) -> str:
        """Python source code of the hostile payload to detonate."""
        ...

    @property
    @abc.abstractmethod
    def expectation(self) -> ProbeExpectation:
        """Expected sandbox verdict for this probe."""
        ...

    def setup(self) -> None:
        """Called before detonation.  Override for custom preparation."""

    def teardown(self) -> None:
        """Called after detonation.  Override for custom cleanup."""
