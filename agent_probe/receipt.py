"""Authenticated receipts and stable exit-code mapping."""

from __future__ import annotations

from typing import Any

from .canonical import sha256_hex
from .contract import sign_envelope, verify_envelope

EXIT_ALLOW = 0
EXIT_DENY = 2
EXIT_RUNTIME_FAILURE = 3
EXIT_EVIDENCE_FAILURE = 4
EXIT_INVALID_RECEIPT = 5
EXIT_CLEANUP_FAILURE = 6

EXECUTION = {"COMPLETE", "INFRASTRUCTURE_FAILED"}
GATES = {"ALLOW", "DENY", "RESCOPE_REQUIRED", "EVALUATION_INCOMPLETE"}
CLEANUP = {"VERIFIED", "UNVERIFIED"}


def build_receipt_envelope(
    *,
    job_manifest: dict[str, Any],
    road_frozen: dict[str, Any],
    road_walked: dict[str, Any],
    road_diff: dict[str, Any],
    guest_evidence_manifest: dict[str, Any],
    host_lifecycle: dict[str, Any],
    execution_status: str,
    gate_decision: str,
    cleanup_status: str,
    observer_key: bytes,
) -> dict[str, Any]:
    if execution_status not in EXECUTION or gate_decision not in GATES or cleanup_status not in CLEANUP:
        raise ValueError("receipt status enum is invalid")
    if gate_decision == "ALLOW" and (execution_status != "COMPLETE" or cleanup_status != "VERIFIED"):
        raise ValueError("ALLOW requires complete execution and verified cleanup")
    payload = {
        "receipt_version": "cindermote.agent-probe-receipt/v1",
        "profile": "agent-probe/v0",
        "job_id": job_manifest["job_id"],
        "target_hash": job_manifest["target"]["target_hash"],
        "road_frozen_hash": sha256_hex(road_frozen),
        "road_walked_hash": sha256_hex(road_walked),
        "road_diff_hash": sha256_hex(road_diff),
        "guest_evidence_root": guest_evidence_manifest["guest_evidence_root"],
        "host_lifecycle_root": host_lifecycle["host_lifecycle_root"],
        "execution_status": execution_status,
        "gate_decision": gate_decision,
        "cleanup_status": cleanup_status,
        "artifact_disposition": "HOLD" if gate_decision in {"ALLOW", "RESCOPE_REQUIRED"} else "REJECT",
        "witnesses": {
            "guest_complete": bool(guest_evidence_manifest.get("complete")),
            "egress_complete": bool(host_lifecycle.get("egress_witness_complete")),
            "cleanup_complete": bool(host_lifecycle.get("cleanup_verified")),
        },
    }
    if gate_decision == "ALLOW" and not all(payload["witnesses"].values()):
        raise ValueError("ALLOW requires complete witnesses")
    return sign_envelope(payload, "cindermote.agent-probe-receipt/v1", observer_key)


def derive_exit_code(envelope: Any, observer_key: bytes) -> int:
    if not verify_envelope(envelope, observer_key, "cindermote.agent-probe-receipt/v1"):
        return EXIT_INVALID_RECEIPT
    receipt = envelope["payload"]
    if not isinstance(receipt, dict) or receipt.get("receipt_version") != "cindermote.agent-probe-receipt/v1":
        return EXIT_INVALID_RECEIPT
    if receipt.get("cleanup_status") != "VERIFIED":
        return EXIT_CLEANUP_FAILURE
    if receipt.get("execution_status") != "COMPLETE":
        return EXIT_RUNTIME_FAILURE
    decision = receipt.get("gate_decision")
    if decision == "ALLOW":
        if not all(receipt.get("witnesses", {}).values()):
            return EXIT_EVIDENCE_FAILURE
        return EXIT_ALLOW
    if decision in {"DENY", "RESCOPE_REQUIRED"}:
        return EXIT_DENY
    if decision == "EVALUATION_INCOMPLETE":
        return EXIT_EVIDENCE_FAILURE
    return EXIT_INVALID_RECEIPT
