"""Deterministic Cindermote Policy Gate.

The Policy Gate is autonomous but is not the Human Gate. A matching local
override is applied only after the scoring matrix and is recorded separately.
"""

from __future__ import annotations

import json
from pathlib import Path

from cindermote.broker.broker import validate_outward_report
from cindermote.observer.detectors import KNOWN_BAD_RULES


UNOVERRIDABLE_RULES = {
    "telemetry_loss",
    "broker_failure",
    "firecracker_runtime_failure",
    "isolation_admission_failure",
    "purge_failure",
    "web_browser_execution_failed",
    "web_browser_lifecycle_incomplete",
    "web_browser_sandbox_inactive",
    "web_browser_sandbox_unknown",
    "web_browser_telemetry_loss",
    "web_cdp_telemetry_loss",
    "web_egress_telemetry_loss",
    "web_event_budget_exceeded",
    "web_evidence_count_mismatch",
    "web_evidence_schema_invalid",
    "web_evidence_sequence_gap",
    "web_host_guest_network_mismatch",
    "web_host_guest_network_unknown",
    "web_navigation_missing",
    "web_redirect_budget_exceeded",
    "web_vm_execution_failed",
    "web_vm_lifecycle_incomplete",
    "web_vm_telemetry_loss",
}


def _load_override(source: str | Path | dict | None) -> dict:
    if source is None:
        return {}
    if isinstance(source, dict):
        return source
    path = Path(source)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    if not isinstance(value, dict):
        raise ValueError("override.json must contain an object")
    return value


def _decision_for_job(overrides: dict, job_id: str) -> str:
    candidate = overrides.get(job_id)
    if isinstance(candidate, str):
        decision = candidate
    elif isinstance(candidate, dict):
        decision = candidate.get("decision", "none")
    else:
        entries = overrides.get("overrides", [])
        decision = "none"
        if isinstance(entries, list):
            for item in entries:
                if isinstance(item, dict) and item.get("job_id") == job_id:
                    decision = item.get("decision", "none")
                    break
    return decision if decision in {"ALLOW", "DENY"} else "none"


def apply_scoring_matrix(
    outward_report: dict,
    override_json: str | Path | dict | None,
    job_id: str,
) -> dict:
    validate_outward_report(outward_report)
    evidence = {item["rule_id"]: item["count"] for item in outward_report["evidence"]}

    if any(evidence.get(rule_id, 0) > 0 for rule_id in KNOWN_BAD_RULES):
        policy_decision = "DENY"
        reason = "known_bad_behavior_detected"
    elif outward_report["canaries_tripped"] and evidence.get("cred_harvest_pattern", 0):
        policy_decision = "DENY"
        reason = "canary_credential_accessed"
    elif evidence.get("network_exfil_attempt", 0) or evidence.get("dns_tunnel_probe", 0):
        policy_decision = "DENY"
        reason = "network_egress_attempted"
    elif evidence.get("sandbox_probing", 0) >= 3:
        policy_decision = "DENY"
        reason = "repeated_sandbox_probing"
    elif evidence.get("exec_spawn_chain", 0) or evidence.get("fs_suspicious_write", 0):
        policy_decision = "DENY"
        reason = "anomalous_behavior_pattern"
    elif (
        not outward_report["evidence"]
        and not outward_report["canaries_tripped"]
        and outward_report["capabilities_requested"] in ([], ["browser.navigate"])
    ):
        policy_decision = "ALLOW"
        reason = (
            "bounded_browser_navigation_clean"
            if outward_report["capabilities_requested"]
            else "no_anomaly_detected"
        )
    else:
        policy_decision = "DENY"
        reason = "uncertain_classification"

    human_override = _decision_for_job(_load_override(override_json), job_id)
    if evidence.get("payload_observation_incomplete", 0) > 0:
        # The payload observation never completed (interpreter startup,
        # snapshot/library load, or observer failure). Missing evidence is not
        # classifiable; no authority may promote it to a verdict.
        return {
            "policy_gate_decision": "EVALUATION_INCOMPLETE",
            "policy_gate_reason": "payload_observation_incomplete",
            "human_gate_override": human_override,
            "final_decision": "EVALUATION_INCOMPLETE",
            "final_authority": "fail_closed_incomplete_observation",
            "override_blocked_by_fail_closed": human_override == "ALLOW",
        }
    fail_closed = any(evidence.get(rule_id, 0) > 0 for rule_id in UNOVERRIDABLE_RULES)
    if fail_closed:
        final_decision = "DENY"
        final_authority = "fail_closed_infrastructure_gate"
    elif human_override in {"ALLOW", "DENY"}:
        final_decision = human_override
        final_authority = "human_gate_override"
    else:
        final_decision = policy_decision
        final_authority = "policy_gate_autonomous"

    return {
        "policy_gate_decision": policy_decision,
        "policy_gate_reason": reason,
        "human_gate_override": human_override,
        "final_decision": final_decision,
        "final_authority": final_authority,
        "override_blocked_by_fail_closed": bool(fail_closed and human_override == "ALLOW"),
    }
