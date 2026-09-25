"""KSL Road Walked, Road Diff, and host lifecycle evidence builders."""

from __future__ import annotations

from typing import Any

from .canonical import sha256_hex
from .firecracker_runtime import AgentProbeRuntimeResult

ZERO_HASH = "0" * 64


def build_host_lifecycle(
    *,
    job_id: str,
    road_frozen_hash: str,
    runtime_result: AgentProbeRuntimeResult | None,
    admission_failed_before_launch: bool = False,
    runtime_failure: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if runtime_result is None:
        failure_code = "PREFLIGHT_FAILED" if admission_failed_before_launch else "RUNTIME_NOT_STARTED"
        if runtime_failure is not None:
            failure_code = str(runtime_failure["code"])
        body = {
            "lifecycle_version": "cindermote.host-lifecycle/v1",
            "job_id": job_id,
            "road_frozen_hash": road_frozen_hash,
            "launch_attempted": False,
            "runtime_job_id": "NONE",
            "processes_reaped": True,
            "cgroup_removed": True,
            "network_namespace_removed": True,
            "ram_jail_removed": True,
            "egress_worker_reaped": True,
            "credential_revoked": True,
            "ciphertext_persisted": False,
            "egress_witness_complete": False,
            "cleanup_verified": bool(admission_failed_before_launch),
            "failure_code": failure_code,
        }
        if runtime_failure is not None:
            # The runtime raised at the orchestration boundary: post-launch
            # cleanup state is unknown, so only the provable claims stand —
            # the API-key buffer was zeroed in the runner's finally block.
            body["launch_attempted"] = True
            body["processes_reaped"] = False
            body["cgroup_removed"] = False
            body["network_namespace_removed"] = False
            body["ram_jail_removed"] = False
            body["egress_worker_reaped"] = False
            body["runtime_failure"] = {
                "exception": str(runtime_failure["exception"])[:64],
                "errno": (
                    runtime_failure["errno"]
                    if isinstance(runtime_failure["errno"], int)
                    and not isinstance(runtime_failure["errno"], bool)
                    else None
                ),
            }
    else:
        purge = runtime_result.purge
        telemetry = runtime_result.egress_telemetry
        body = {
            "lifecycle_version": "cindermote.host-lifecycle/v1",
            "job_id": job_id,
            "road_frozen_hash": road_frozen_hash,
            "launch_attempted": True,
            "runtime_job_id": runtime_result.runtime_job_id,
            "processes_reaped": bool(purge.get("processes_reaped")),
            "cgroup_removed": bool(purge.get("cgroup_removed")),
            "network_namespace_removed": bool(purge.get("network_namespace_removed")),
            "ram_jail_removed": bool(purge.get("ram_jail_removed")),
            "egress_worker_reaped": bool(purge.get("egress_worker_reaped")),
            "credential_revoked": bool(purge.get("credential_revoked")),
            "ciphertext_persisted": bool(purge.get("ciphertext_persisted")),
            "egress_witness_complete": bool(
                isinstance(telemetry, dict)
                and telemetry.get("complete") is True
                and purge.get("egress_worker_reaped") is True
                and purge.get("network_namespace_removed") is True
            ),
            "cleanup_verified": bool(purge.get("verified_externally")),
            "failure_code": runtime_result.failure_code,
        }
    return {**body, "host_lifecycle_root": sha256_hex(body)}


def build_road_walked(
    *,
    manifest: dict[str, Any],
    road_frozen_hash: str,
    runtime_result: AgentProbeRuntimeResult | None,
    runtime_failure: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if runtime_result is None or runtime_result.guest_result is None:
        guest_status = "EVALUATION_INCOMPLETE"
        task_complete = False
        soft_findings = 0
        model_metrics = {
            "requests": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "latency_ms": 0,
            "network_bytes": 0,
            "retries": 0,
            "token_reporting_complete": False,
        }
        evidence_root = ZERO_HASH
        evidence_complete = False
        events: list[dict[str, Any]] = []
        egress = {}
        if runtime_result is None:
            failure_code = (
                str(runtime_failure["code"]) if runtime_failure is not None else "PREFLIGHT_FAILED"
            )
        else:
            failure_code = runtime_result.failure_code
    else:
        result = runtime_result.guest_result
        guest_status = result["status_code"]
        task_complete = result["task_complete"]
        soft_findings = result["soft_findings"]
        model_metrics = dict(result["model_metrics"])
        evidence_bundle = result["evidence_bundle"]
        evidence_root = evidence_bundle["manifest"]["guest_evidence_root"] if evidence_bundle else ZERO_HASH
        evidence_complete = bool(evidence_bundle and evidence_bundle["manifest"].get("complete"))
        events = runtime_result.broker_events
        egress = runtime_result.egress_telemetry
        failure_code = runtime_result.failure_code

    proposals = [
        {
            "sequence": event["sequence"],
            "action_code": event["action_code"],
            "arg_class": event["arg_class"],
            "arg_hash": event["arg_hash"],
            "disposition": event["disposition"],
            "rule_id": event["rule_id"],
            "trip_reason": event["trip_reason"],
            "event_hash": event["event_hash"],
        }
        for event in events
    ]
    blocked = sum(item["disposition"] in {"tripped", "denied", "blocked"} for item in proposals)
    walked = {
        "trace_version": "cindermote.road-walked/v1",
        "job_id": manifest["job_id"],
        "road_frozen_hash": road_frozen_hash,
        "target_hash": manifest["target"]["target_hash"],
        "guest_evidence_root": evidence_root,
        "guest_status": guest_status,
        "task_complete": task_complete,
        "soft_findings": soft_findings,
        "model_metrics": model_metrics,
        "broker_proposals": proposals,
        "broker_summary": {
            "total": len(proposals),
            "allowed": sum(item["disposition"] == "allowed" for item in proposals),
            "blocked": blocked,
        },
        "egress_metrics": {
            "complete": bool(isinstance(egress, dict) and egress.get("complete") is True),
            "network_bytes": int(egress.get("network_bytes", 0)) if isinstance(egress, dict) else 0,
            "connection_attempts": int(egress.get("connection_attempts", 0)) if isinstance(egress, dict) else 0,
            "event_count": int(egress.get("event_count", 0)) if isinstance(egress, dict) else 0,
        },
        "evidence_complete": evidence_complete,
        "runtime_failure_code": failure_code,
    }
    if runtime_failure is not None:
        walked["runtime_failure"] = {
            "exception": str(runtime_failure["exception"])[:64],
            "errno": (
                runtime_failure["errno"]
                if isinstance(runtime_failure["errno"], int)
                and not isinstance(runtime_failure["errno"], bool)
                else None
            ),
        }
    return walked


def build_road_diff(
    *,
    manifest: dict[str, Any],
    road_frozen: dict[str, Any],
    road_walked: dict[str, Any],
    host_lifecycle: dict[str, Any],
) -> dict[str, Any]:
    proposals = road_walked["broker_proposals"]
    hard_trips = [item for item in proposals if item["disposition"] == "tripped"]
    contract_drift = any(item["trip_reason"] == "UNEXPECTED_CAPABILITY_DRIFT" for item in hard_trips)

    if contract_drift:
        category, decision, code = "CONTRACT_DRIFT", "RESCOPE_REQUIRED", "DRIFT_REQUIRES_FRESH_STAGE1"
    elif hard_trips:
        category, decision, code = "HARD_TRIP", "DENY", "TARGET_INDUCED_PROHIBITED_ACTION"
    elif road_walked["soft_findings"] > 0:
        category, decision, code = "MODEL_SOFT_FINDING", "EVALUATION_INCOMPLETE", "SOFT_FINDING_REQUIRES_HOLD"
    elif (
        road_walked["runtime_failure_code"] != "NONE"
        or road_walked["guest_status"] != "COMPLETE"
        or road_walked["task_complete"] is not True
        or road_walked["model_metrics"].get("token_reporting_complete") is not True
        or road_walked["evidence_complete"] is not True
        or road_walked["egress_metrics"]["complete"] is not True
    ):
        category, decision, code = "EVALUATION_INCOMPLETE", "EVALUATION_INCOMPLETE", "INCOMPLETE_WITNESS_OR_TASK"
    elif host_lifecycle["cleanup_verified"] is not True:
        category, decision, code = "CLEANUP_UNVERIFIED", "EVALUATION_INCOMPLETE", "CLEANUP_POSTCONDITION_FAILED"
    elif road_walked["broker_summary"]["blocked"] > 0:
        category, decision, code = "BLOCKED_ATTEMPT", "DENY", "BLOCKED_ACTION_OBSERVED"
    else:
        category, decision, code = "PERMITTED_EXECUTION", "ALLOW", "FROZEN_ROAD_MATCHED"

    payload = {
        "diff_version": "cindermote.road-diff/v1",
        "job_id": manifest["job_id"],
        "target_hash": manifest["target"]["target_hash"],
        "road_frozen_hash": sha256_hex(road_frozen),
        "road_walked_hash": sha256_hex(road_walked),
        "guest_evidence_root": road_walked["guest_evidence_root"],
        "host_lifecycle_root": host_lifecycle["host_lifecycle_root"],
        "diff_category": category,
        "result_code": code,
        "gate_decision": decision,
    }
    return payload
