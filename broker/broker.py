"""Deny-by-default capability broker and schema egress gate."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from cindermote.observer.detectors import DetectorEngine, KNOWN_BAD_RULES


REPORT_KEYS = {
    "risk_level",
    "evidence",
    "capabilities_requested",
    "destinations",
    "canaries_tripped",
    "uncertainty",
}
EVIDENCE_KEYS = {"tap_category", "rule_id", "count"}
RISK_LEVELS = {"benign", "suspicious", "hostile"}
TAP_CATEGORIES = {
    "filesystem",
    "process_tree",
    "dns",
    "network_flows",
    "cred_access",
    "syscall_class",
    "resource_use",
    "canary_trips",
}


class OutwardReportSchemaError(ValueError):
    """Raised when an outward report cannot cross the broker boundary."""


def _bounded_string_list(value: object, name: str, limit: int = 256) -> list[str]:
    if not isinstance(value, list) or len(value) > limit:
        raise OutwardReportSchemaError(f"{name} must be a bounded list")
    if any(not isinstance(item, str) or len(item) > 512 for item in value):
        raise OutwardReportSchemaError(f"{name} contains an invalid string")
    return value


def validate_outward_report(report: dict) -> None:
    if not isinstance(report, dict) or set(report) != REPORT_KEYS:
        raise OutwardReportSchemaError("outward_report has missing or extra fields")
    if report["risk_level"] not in RISK_LEVELS:
        raise OutwardReportSchemaError("invalid risk_level")
    if not isinstance(report["evidence"], list) or len(report["evidence"]) > 512:
        raise OutwardReportSchemaError("evidence must be a bounded list")
    for item in report["evidence"]:
        if not isinstance(item, dict) or set(item) != EVIDENCE_KEYS:
            raise OutwardReportSchemaError("malformed evidence item")
        if item["tap_category"] not in TAP_CATEGORIES:
            raise OutwardReportSchemaError("invalid tap_category")
        if not isinstance(item["rule_id"], str) or not 1 <= len(item["rule_id"]) <= 128:
            raise OutwardReportSchemaError("invalid evidence rule_id")
        if not isinstance(item["count"], int) or item["count"] < 0:
            raise OutwardReportSchemaError("evidence count must be uint")
    _bounded_string_list(report["capabilities_requested"], "capabilities_requested")
    _bounded_string_list(report["destinations"], "destinations")
    _bounded_string_list(report["canaries_tripped"], "canaries_tripped")
    uncertainty = report["uncertainty"]
    if isinstance(uncertainty, bool) or not isinstance(uncertainty, (int, float)):
        raise OutwardReportSchemaError("uncertainty must be numeric")
    if not 0.0 <= float(uncertainty) <= 1.0:
        raise OutwardReportSchemaError("uncertainty is outside 0.0-1.0")


@dataclass
class CapabilityBroker:
    """Consumes typed telemetry and grants no ambient capability."""

    detector: DetectorEngine
    requested: list[str] = field(default_factory=list)
    granted: list[str] = field(default_factory=list)
    denied: list[str] = field(default_factory=list)

    def request_capabilities(self, capabilities: Iterable[str]) -> None:
        normalized: list[str] = []
        for capability in capabilities:
            if not isinstance(capability, str) or not capability or len(capability) > 128:
                raise ValueError("capability names must be bounded strings")
            if capability not in normalized:
                normalized.append(capability)
        self.requested = normalized
        self.granted = []
        self.denied = list(normalized)

    def build_report(self, *, uncertainty: float = 0.0) -> dict:
        evidence = self.detector.evidence()
        rule_ids = {item["rule_id"] for item in evidence}
        if rule_ids & KNOWN_BAD_RULES:
            risk_level = "hostile"
        elif evidence or self.denied:
            risk_level = "suspicious"
        else:
            risk_level = "benign"

        report = {
            "risk_level": risk_level,
            "evidence": evidence,
            "capabilities_requested": list(self.requested),
            "destinations": sorted(self.detector.destinations),
            "canaries_tripped": sorted(self.detector.canaries),
            "uncertainty": max(0.0, min(1.0, float(uncertainty))),
        }
        validate_outward_report(report)
        return report
