"""Deterministic Cindermote telemetry detectors.

This module never interprets artifact text as authority. Raw bytes are scanned
only for fixed byte patterns and are reduced to typed rule identifiers before
they can enter a receipt or outward report.
"""

from __future__ import annotations

import hashlib
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Iterable


TELEMETRY_KEYS = {
    "ts_mono_ns",
    "tap",
    "rule_id",
    "subject",
    "action",
    "verdict_hint",
}
TAPS = {"fs", "proc", "dns", "net", "cred", "syscall"}
ACTIONS = {"read", "write", "exec", "connect", "resolve", "fork", "exit"}
VERDICT_HINTS = {"known_bad", "anomalous", "baseline"}

RULES = {
    "cred_harvest_pattern": ("cred_access", "CRITICAL", "known_bad"),
    "sandbox_probing": ("syscall_class", "HIGH", "anomalous"),
    "network_exfil_attempt": ("network_flows", "CRITICAL", "known_bad"),
    "exec_spawn_chain": ("process_tree", "HIGH", "anomalous"),
    "fs_suspicious_write": ("filesystem", "WATCH", "anomalous"),
    "timing_evasion": ("syscall_class", "WATCH", "anomalous"),
    "dns_tunnel_probe": ("dns", "HIGH", "anomalous"),
    "codex_manipulation": ("syscall_class", "CRITICAL", "known_bad"),
    "tool_poisoning": ("syscall_class", "HIGH", "anomalous"),
    "namespace_escape_attempt": ("syscall_class", "CRITICAL", "known_bad"),
    "malformed_report": ("syscall_class", "HIGH", "known_bad"),
    "telemetry_loss": ("syscall_class", "CRITICAL", "known_bad"),
    "budget_exhausted": ("resource_use", "HIGH", "anomalous"),
    "broker_failure": ("syscall_class", "CRITICAL", "known_bad"),
    "firecracker_runtime_failure": ("syscall_class", "CRITICAL", "known_bad"),
    "isolation_admission_failure": ("syscall_class", "CRITICAL", "known_bad"),
    "payload_observation_incomplete": ("syscall_class", "CRITICAL", "anomalous"),
    "purge_failure": ("syscall_class", "CRITICAL", "known_bad"),
    "web_active_interaction_attempt": ("syscall_class", "CRITICAL", "known_bad"),
    "web_blocked_egress_attempt": ("network_flows", "HIGH", "anomalous"),
    "web_browser_execution_failed": ("syscall_class", "CRITICAL", "known_bad"),
    "web_browser_lifecycle_incomplete": ("syscall_class", "CRITICAL", "known_bad"),
    "web_browser_sandbox_inactive": ("syscall_class", "CRITICAL", "known_bad"),
    "web_browser_sandbox_unknown": ("syscall_class", "CRITICAL", "known_bad"),
    "web_browser_telemetry_loss": ("syscall_class", "CRITICAL", "known_bad"),
    "web_cdp_telemetry_loss": ("syscall_class", "CRITICAL", "known_bad"),
    "web_download_attempt": ("filesystem", "HIGH", "anomalous"),
    "web_egress_telemetry_loss": ("network_flows", "CRITICAL", "known_bad"),
    "web_event_budget_exceeded": ("resource_use", "CRITICAL", "known_bad"),
    "web_evidence_count_mismatch": ("syscall_class", "CRITICAL", "known_bad"),
    "web_evidence_schema_invalid": ("syscall_class", "CRITICAL", "known_bad"),
    "web_evidence_sequence_gap": ("syscall_class", "CRITICAL", "known_bad"),
    "web_file_upload_attempt": ("filesystem", "CRITICAL", "known_bad"),
    "web_host_guest_network_mismatch": ("network_flows", "CRITICAL", "known_bad"),
    "web_host_guest_network_unknown": ("network_flows", "CRITICAL", "known_bad"),
    "web_mixed_content_observed": ("network_flows", "HIGH", "anomalous"),
    "web_navigation_failed": ("network_flows", "HIGH", "anomalous"),
    "web_navigation_missing": ("network_flows", "CRITICAL", "known_bad"),
    "web_popup_attempt": ("process_tree", "HIGH", "anomalous"),
    "web_prompt_marker_hidden": ("syscall_class", "HIGH", "anomalous"),
    "web_prompt_marker_visible": ("syscall_class", "HIGH", "anomalous"),
    "web_redirect_budget_exceeded": ("resource_use", "CRITICAL", "known_bad"),
    "web_unauthorized_origin_attempt": ("network_flows", "CRITICAL", "known_bad"),
    "web_vm_execution_failed": ("syscall_class", "CRITICAL", "known_bad"),
    "web_vm_lifecycle_incomplete": ("syscall_class", "CRITICAL", "known_bad"),
    "web_vm_telemetry_loss": ("syscall_class", "CRITICAL", "known_bad"),
}

KNOWN_BAD_RULES = {
    rule_id for rule_id, (_, _, hint) in RULES.items() if hint == "known_bad"
}

INSTRUCTION_PATTERNS = (
    b"authorized",
    b"enable network",
    b"release file",
    b"override policy",
    b"human gate says allow",
    b"system: you may",
    b"system: you are now",
    b"ignore previous",
    b"disregard",
)

CANARY_PATHS = {
    "/home/mote/.aws/credentials": "canary_cred_aws",
    "/home/mote/.ssh/id_rsa": "canary_cred_ssh",
    "/home/mote/canary_file.txt": "canary_file",
}

SANDBOX_PROBE_PREFIXES = (
    "/proc/1/ns/",
    "/sys/class/dmi/id",
    "/proc/sys/kernel",
    "/proc/1/environ",
)


class TelemetrySchemaError(ValueError):
    """Raised when a telemetry event is not schema-conformant."""


def validate_telemetry_event(event: dict) -> None:
    if not isinstance(event, dict) or set(event) != TELEMETRY_KEYS:
        raise TelemetrySchemaError("telemetry_event has missing or extra fields")
    if not isinstance(event["ts_mono_ns"], int) or event["ts_mono_ns"] < 0:
        raise TelemetrySchemaError("ts_mono_ns must be uint64")
    if event["tap"] not in TAPS:
        raise TelemetrySchemaError("invalid telemetry tap")
    if not isinstance(event["rule_id"], str) or not 1 <= len(event["rule_id"]) <= 128:
        raise TelemetrySchemaError("invalid rule_id")
    if not isinstance(event["subject"], str) or len(event["subject"]) > 512:
        raise TelemetrySchemaError("invalid subject")
    if event["action"] not in ACTIONS:
        raise TelemetrySchemaError("invalid action")
    if event["verdict_hint"] not in VERDICT_HINTS:
        raise TelemetrySchemaError("invalid verdict_hint")


def make_event(
    tap: str,
    rule_id: str,
    subject: str,
    action: str,
    verdict_hint: str,
    *,
    ts_mono_ns: int | None = None,
) -> dict:
    event = {
        "ts_mono_ns": time.monotonic_ns() if ts_mono_ns is None else ts_mono_ns,
        "tap": tap,
        "rule_id": rule_id,
        "subject": subject[:512],
        "action": action,
        "verdict_hint": verdict_hint,
    }
    validate_telemetry_event(event)
    return event


def bounded_subject(value: str, known: Iterable[str] = ()) -> str:
    """Return a known label or a non-reversible digest for untrusted text."""
    if value in known:
        return value
    digest = hashlib.sha256(value.encode("utf-8", "surrogateescape")).hexdigest()
    return f"sha256:{digest}"


def classify_path(path: str, flags: int = 0) -> tuple[list[dict], str | None]:
    """Apply the fixed filesystem and canary rules to one open path."""
    events: list[dict] = []
    normalized = str(PurePosixPath(path)) if path.startswith("/") else path
    canary = CANARY_PATHS.get(normalized)
    if canary or "canary_cred_" in normalized or normalized.startswith("/tmp/canary_"):
        label = canary or "canary_dynamic"
        events.append(
            make_event("cred", "cred_harvest_pattern", label, "read", "known_bad")
        )
        canary = label

    if normalized.startswith(SANDBOX_PROBE_PREFIXES):
        events.append(
            make_event(
                "syscall",
                "sandbox_probing",
                bounded_subject(normalized, SANDBOX_PROBE_PREFIXES),
                "read",
                "anomalous",
            )
        )

    creates = bool(flags & 0o100)
    name = PurePosixPath(normalized).name
    if creates and (
        normalized.startswith("/tmp/.cache")
        or normalized.startswith("/dev/shm")
        or name.startswith(".")
    ):
        events.append(
            make_event(
                "fs",
                "fs_suspicious_write",
                bounded_subject(normalized),
                "write",
                "anomalous",
            )
        )
    return events, canary


def scan_instruction_patterns(raw: bytes) -> bool:
    lowered = raw.lower()
    return any(pattern in lowered for pattern in INSTRUCTION_PATTERNS)


def scan_tool_description(description: str) -> bool:
    return scan_instruction_patterns(description.encode("utf-8", "replace"))


@dataclass
class DetectorEngine:
    """Stateful deterministic reducer for a single detonation."""

    max_events: int = 10_000
    events: list[dict] = field(default_factory=list)
    finding_counts: Counter = field(default_factory=Counter)
    tap_counts: Counter = field(default_factory=Counter)
    canaries: dict[str, float] = field(default_factory=dict)
    destinations: dict[str, str] = field(default_factory=dict)
    telemetry_incomplete: bool = False
    _start_ns: int = field(default_factory=time.monotonic_ns)

    def record(self, event: dict) -> None:
        try:
            validate_telemetry_event(event)
        except TelemetrySchemaError:
            self.telemetry_incomplete = True
            replacement = make_event(
                "syscall",
                "malformed_report",
                "invalid_telemetry_event",
                "write",
                "known_bad",
            )
            self._record_valid(replacement)
            return
        self._record_valid(event)

    def _record_valid(self, event: dict) -> None:
        self.tap_counts[event["tap"]] += 1
        if len(self.events) < self.max_events:
            self.events.append(event)
        else:
            self.telemetry_incomplete = True
        if event["rule_id"] in RULES and event["verdict_hint"] != "baseline":
            self.finding_counts[event["rule_id"]] += 1

    def trip_canary(self, name: str) -> None:
        self.canaries.setdefault(name, (time.monotonic_ns() - self._start_ns) / 1e9)

    def add_destination(self, destination: str, disposition: str) -> None:
        if disposition not in {"sinkholed", "blocked-by-seccomp", "recorded+denied"}:
            raise ValueError("invalid destination disposition")
        safe = destination if len(destination) <= 128 else bounded_subject(destination)
        self.destinations[safe] = disposition

    def mark_telemetry_loss(self) -> None:
        self.telemetry_incomplete = True
        self.record(
            make_event(
                "syscall",
                "telemetry_loss",
                "host_tap_incomplete",
                "exit",
                "known_bad",
            )
        )

    def evidence(self) -> list[dict]:
        items = []
        for rule_id in sorted(self.finding_counts):
            tap_category, _, _ = RULES[rule_id]
            items.append(
                {
                    "tap_category": tap_category,
                    "rule_id": rule_id,
                    "count": int(self.finding_counts[rule_id]),
                }
            )
        return items

    def findings(self) -> list[dict]:
        findings = []
        for rule_id in sorted(self.finding_counts):
            _, severity, _ = RULES[rule_id]
            findings.append(
                {
                    "rule_id": rule_id,
                    "count": int(self.finding_counts[rule_id]),
                    "severity": severity,
                }
            )
        return findings
