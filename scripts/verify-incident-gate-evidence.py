#!/usr/bin/env python3
"""Verify an Incident Gate run manifest and every signed child receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from incident_gate import CINDER_PROBES, RISK_RANK
from observer.receipt import validate_receipt, verify_signature


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run_file(run_root: Path, relative_path: Any) -> Path:
    if not isinstance(relative_path, str) or not relative_path:
        raise ValueError("child receipt path must be a non-empty string")
    if Path(relative_path).is_absolute():
        raise ValueError("child receipt path must be relative")
    root = run_root.resolve(strict=True)
    candidate = (root / relative_path).resolve(strict=True)
    if candidate == root or root not in candidate.parents or not candidate.is_file():
        raise ValueError("child receipt path escapes the run directory")
    return candidate


def verify_run(
    run_root: Path,
    *,
    key_path: Path,
    policy_path: Path,
    expect_all: bool = False,
) -> dict[str, Any]:
    run_root = run_root.resolve(strict=True)
    manifest_path = run_root / "cinder-incident-gate.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("incident-gate manifest must be an object")
    key = key_path.read_bytes()
    if len(key) != 32:
        raise ValueError("observer key must contain exactly 32 bytes")
    policy = json.loads(policy_path.read_text(encoding="utf-8"))

    errors: list[str] = []
    warnings: list[str] = []
    if manifest.get("gate") != "cinder-incident-gate-v3":
        errors.append("invalid incident-gate manifest")
    if manifest.get("run_id") != run_root.name:
        errors.append("manifest run_id does not match its directory")
    children = manifest.get("child_receipts", [])
    results = manifest.get("results", [])
    if not isinstance(children, list) or not isinstance(results, list):
        errors.append("manifest child_receipts and results must be lists")
        children = []
        results = []

    checked: list[dict[str, Any]] = []
    seen_jobs: set[str] = set()
    receipts_by_job: dict[str, dict[str, Any]] = {}
    for index, entry in enumerate(children):
        record: dict[str, Any] = {"index": index, "valid": False}
        checked.append(record)
        if not isinstance(entry, dict):
            errors.append(f"child {index}: manifest entry is not an object")
            continue
        job_id = entry.get("job_id")
        record["job_id"] = job_id
        if not isinstance(job_id, str) or not job_id or job_id in seen_jobs:
            errors.append(f"child {index}: invalid or duplicate job_id")
            continue
        seen_jobs.add(job_id)
        try:
            receipt_path = _run_file(run_root, entry.get("path"))
            actual_hash = _sha256(receipt_path)
            record["path"] = str(receipt_path.relative_to(run_root))
            record["sha256"] = actual_hash
            if actual_hash != entry.get("sha256"):
                raise ValueError("receipt hash does not match manifest")
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            validate_receipt(receipt, active_policy=policy)
            if not verify_signature(receipt, key):
                raise ValueError("receipt signature is invalid")
            if receipt.get("identity", {}).get("job_id") != job_id:
                raise ValueError("receipt job_id does not match manifest")
            receipts_by_job[job_id] = receipt
            record["valid"] = True
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            errors.append(f"child {job_id}: {exc}")

    result_jobs = {
        result.get("job_id")
        for result in results
        if isinstance(result, dict) and isinstance(result.get("job_id"), str)
    }
    declared_count = manifest.get("probe_count")
    if declared_count != len(children) or len(results) != len(children):
        errors.append("manifest probe_count, results, and child receipts disagree")
    if result_jobs != seen_jobs:
        errors.append("manifest result job_ids and child receipt job_ids disagree")
    canonical_probes = {probe.name: probe for probe in CINDER_PROBES}
    seen_names: set[str] = set()
    for index, result in enumerate(results):
        if not isinstance(result, dict):
            continue
        job_id = result.get("job_id")
        name = result.get("name")
        if not isinstance(name, str) or name in seen_names or name not in canonical_probes:
            errors.append(f"result {index}: invalid or duplicate probe name")
            continue
        seen_names.add(name)
        receipt = receipts_by_job.get(job_id) if isinstance(job_id, str) else None
        if receipt is None:
            continue
        probe = canonical_probes[name]
        expected = {
            "expected_risk": probe.expected_risk,
            "expected_decision": probe.expected_decision,
            "expected_rules": sorted(probe.expected_rules),
        }
        for field, value in expected.items():
            if result.get(field) != value:
                errors.append(f"result {name}: {field} disagrees with the probe definition")

        outward = receipt["outward_report"]
        gate = receipt["gate"]
        isolation = receipt["isolation"]
        purge = receipt["purge"]
        observation = receipt.get("observation", {})
        observed_risk = outward.get("risk_level", "unknown")
        observed_decision = gate.get("final_decision", "UNKNOWN")
        observed_rules = sorted(
            finding["rule_id"]
            for finding in receipt["detector_findings"]
            if isinstance(finding, dict) and isinstance(finding.get("rule_id"), str)
        )
        isolation_confirmed = (
            isolation.get("namespace_used") is True
            and isolation.get("seccomp_loaded") is True
        )
        purge_verified = purge.get("verified_externally") is True
        observation_status = (
            observation.get("status", "EVALUATION_INCOMPLETE")
            if isinstance(observation, dict)
            else "EVALUATION_INCOMPLETE"
        )
        if observation_status != "COMPLETE":
            observation_status = "EVALUATION_INCOMPLETE"
        risk_ok = RISK_RANK.get(observed_risk, -1) >= RISK_RANK[probe.expected_risk]
        containment_held = (
            risk_ok
            and observed_decision == probe.expected_decision
            and probe.expected_rules.issubset(observed_rules)
            and isolation_confirmed
            and purge_verified
            and observation_status == "COMPLETE"
            and receipt.get("telemetry_incomplete") is False
        )
        derived = {
            "observed_risk": observed_risk,
            "observed_decision": observed_decision,
            "observed_rules": observed_rules,
            "isolation_confirmed": isolation_confirmed,
            "purge_verified": purge_verified,
            "observation_status": observation_status,
            "containment_held": containment_held,
        }
        for field, value in derived.items():
            if result.get(field) != value:
                errors.append(f"result {name}: {field} disagrees with its signed receipt")

    if expect_all and seen_names != set(canonical_probes):
        errors.append("run does not contain the complete canonical probe set")
    result_shape_ok = all(
        isinstance(result, dict)
        and isinstance(result.get("containment_held"), bool)
        and isinstance(result.get("isolation_confirmed"), bool)
        and isinstance(result.get("purge_verified"), bool)
        and isinstance(result.get("observation_status"), str)
        for result in results
    )
    if not result_shape_ok:
        errors.append("manifest containment results are malformed")
    else:
        held_values = [result["containment_held"] for result in results]
        if not isinstance(manifest.get("all_contained"), bool):
            errors.append("manifest all_contained must be a bool")
        elif manifest["all_contained"] != all(held_values):
            errors.append("manifest all_contained disagrees with its results")

        if all(held_values):
            computed_status = "ALL_BOUNDARIES_HELD"
        elif any(
            not result["isolation_confirmed"] or not result["purge_verified"]
            for result in results
        ):
            computed_status = "BOUNDARY_FAILURE_DETECTED"
        elif any(
            result.get("error") or result["observation_status"] != "COMPLETE"
            for result in results
        ):
            computed_status = "EVALUATION_INCOMPLETE"
        else:
            computed_status = "CONTAINMENT_TEST_FAILED"
        declared_status = manifest.get("overall_status")
        if declared_status is None:
            warnings.append("legacy manifest has no overall_status")
        elif declared_status != computed_status:
            errors.append("manifest overall_status disagrees with its results")

    report_path = run_root / "cinder-incident-gate-report.md"
    return {
        "verification_version": 1,
        "run_id": manifest.get("run_id"),
        "overall_status": manifest.get("overall_status"),
        "manifest_sha256": _sha256(manifest_path),
        "report_sha256": _sha256(report_path) if report_path.is_file() else None,
        "child_receipts": checked,
        "verified_receipt_count": sum(bool(item["valid"]) for item in checked),
        "warnings": warnings,
        "errors": errors,
        "verified": not errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_directory", type=Path)
    parser.add_argument("--key", type=Path, default=PROJECT_DIR / ".observer_key")
    parser.add_argument(
        "--policy",
        type=Path,
        default=PROJECT_DIR / "policy" / "hotcell-policy.json",
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--expect-all",
        action="store_true",
        help="require the complete canonical Incident Gate probe set",
    )
    args = parser.parse_args()

    try:
        result = verify_run(
            args.run_directory,
            key_path=args.key,
            policy_path=args.policy,
            expect_all=args.expect_all,
        )
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        result = {"verification_version": 1, "verified": False, "errors": [str(exc)]}
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if result.get("verified") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
