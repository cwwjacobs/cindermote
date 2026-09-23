"""Benign baseline probe — should pass through containment with ALLOW.

This probe does nothing hostile: it reads its own source, does basic math,
and writes to stdout.  The sandbox should observe no rule violations, no
canary trips, and no network activity.  The gate should ALLOW.

This probe exists to prove the pluggable framework works and to provide a
positive-path baseline for regression testing.
"""

from __future__ import annotations

from canaries.probe_base import ProbeBase, ProbeExpectation


class BenignBaselineProbe(ProbeBase):
    @property
    def name(self) -> str:
        return "benign_baseline"

    @property
    def description(self) -> str:
        return "Baseline: benign payload that does nothing hostile"

    @property
    def source(self) -> str:
        return '''\
"""Probe: benign baseline — no hostile activity."""
import sys

# Read own source (inside chroot, so this is a sandbox path)
try:
    with open(sys.argv[0]) as f:
        _ = len(f.read())
except Exception:
    pass

# Basic computation
total = sum(range(100))

print(f"benign_baseline_complete: {total}")
'''

    @property
    def expectation(self) -> ProbeExpectation:
        return ProbeExpectation(
            risk="benign",
            decision="ALLOW",
            rules=frozenset(),
        )
