"""Externally generated and HMAC-signed detonation receipts."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from pathlib import Path
from typing import Any

from cindermote.broker.broker import validate_outward_report
from cindermote.gate.policy_gate import UNOVERRIDABLE_RULES, apply_scoring_matrix
from cindermote.mote.browser_contract import (
    CONTRACT_VERSION as BROWSER_CONTRACT_VERSION,
    MAX_AUTHORIZED_ORIGINS,
    MAX_EVIDENCE_EVENTS,
    REQUIRED_STREAMS as BROWSER_STREAMS,
    normalize_origin,
)
from cindermote.mote.browser_evidence import (
    EVIDENCE_VERSION as BROWSER_EVIDENCE_VERSION,
    TELEMETRY_INCOMPLETE_FINDINGS,
    normalize_connect_authority,
)
from cindermote.observer.detectors import RULES


ARTIFACT_TYPES = {
    "mcp-server",
    "tool-definition",
    "skill-md",
    "python-script",
    "shell-script",
    "browser-probe",
}

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_BROWSER_JOB_ID = re.compile(r"^mf-web-[0-9a-f]{8}$")
_BROWSER_RECEIPT_KEYS = {
    "schema_version",
    "input",
    "runtime",
    "evidence",
    "artifacts",
    "findings",
    "reduction",
}
_BROWSER_INPUT_KEYS = {
    "contract_version",
    "url_sha256",
    "normalized_origin",
    "authorized_origins",
    "request_sha256",
    "policy_hash",
    "navigation_mode",
}
_BROWSER_EVIDENCE_KEYS = {
    "schema_version",
    "sha256",
    "stream_status",
    "events_observed",
}
_BROWSER_REDUCTION_KEYS = {
    "evidence_version",
    "complete",
    "telemetry_incomplete",
    "fail_closed",
    "decision",
    "events_observed",
    "streams",
    "findings",
}
_BROWSER_PURGE_KEYS = {
    "verified_externally",
    "processes_reaped",
    "cgroup_removed",
    "network_namespace_removed",
    "ram_jail_removed",
    "egress_worker_reaped",
}
_BROWSER_ARTIFACT_KEYS = {
    "raw_retained",
    "attestation_complete",
    "dom_sha256",
    "visible_text_sha256",
    "screenshot_sha256",
    "console_event_count",
}
_BROWSER_RUNTIME_BASE_KEYS = {
    "admitted",
    "firecracker_version",
    "firecracker_sha256",
    "jailer_sha256",
    "kernel_sha256",
    "rootfs_sha256",
    "rootfs_receipt_sha256",
    "browser_version",
    "browser_sha256",
    "host_runtime_tmpfs",
    "host_swap_disabled",
    "rootfs_read_only",
    "guest_writes_tmpfs_only",
    "network_mode",
    "mmds_enabled",
    "vmm_identity",
}
_BROWSER_RUNTIME_OPTIONAL_KEYS = {
    "job_image_sha256",
    "jailer_supervision",
    "egress_worker",
    "vmm_exit_code",
    "cgroup_limits",
}
_BROWSER_DESTINATION_LABELS = {
    "proxy_http_origin_allowed",
    "proxy_http_origin_blocked",
    "proxy_connect_authority_allowed",
    "proxy_connect_authority_blocked",
    "browser_cdp_web_origin_allowed",
    "browser_cdp_web_origin_blocked",
}
_BROWSER_CONNECT_LABELS = {
    "proxy_connect_authority_allowed",
    "proxy_connect_authority_blocked",
}
_BROWSER_HTTP_ORIGIN_LABELS = {
    "proxy_http_origin_allowed",
    "proxy_http_origin_blocked",
}
_BROWSER_CDP_ORIGIN_LABELS = {
    "browser_cdp_web_origin_allowed",
    "browser_cdp_web_origin_blocked",
}
_BROWSER_BUDGET_KEYS = {
    "wall_clock_sec",
    "cpu_vcpu",
    "ram_mib",
    "max_network_bytes",
    "max_events",
    "max_redirects",
    "max_tabs",
    "interaction",
    "fs_writes",
}
_LEGACY_ISOLATION_KEYS = {
    "mode",
    "namespace_used",
    "seccomp_loaded",
    "cgroups_used",
    "mlock_used",
}
_LEGACY_PURGE_KEYS = {
    "method",
    "verified_externally",
    "process_group_empty",
    "cgroup_empty",
    "cgroup_removed",
    "job_mount_removed",
    "job_directory_removed",
    "processes_remaining",
    "remaining_host_resources",
}
_LEGACY_GATE_KEYS = {
    "policy_gate_decision",
    "policy_gate_reason",
    "human_gate_override",
    "final_decision",
    "final_authority",
    "override_blocked_by_fail_closed",
}
_DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[1] / "policy" / "hotcell-policy.json"


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _bounded_uint(value: Any, maximum: int = MAX_EVIDENCE_EVENTS) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= maximum
    )


def _canonical_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _load_active_policy(source: str | Path | dict | None) -> dict:
    if source is None:
        source = _DEFAULT_POLICY_PATH
    if isinstance(source, dict):
        policy = source
    else:
        policy = json.loads(Path(source).read_text(encoding="utf-8"))
    if not isinstance(policy, dict):
        raise ValueError("active policy must be a JSON object")
    return policy


def required_isolation_controls(mode: str, policy: dict) -> dict[str, bool]:
    """Derive legacy admission controls from the selected mode and policy."""

    if mode not in {"full-root", "degraded-user"}:
        raise ValueError("invalid legacy isolation mode")
    isolation = policy.get("isolation")
    if not isinstance(isolation, dict):
        raise ValueError("active policy lacks isolation requirements")
    names = (
        "require_network_namespace",
        "require_mount_namespace",
        "require_seccomp",
        "full_root_requires_cgroups",
        "full_root_requires_mlock",
    )
    for name in names:
        if not isinstance(isolation.get(name), bool):
            raise ValueError(f"active policy isolation.{name} must be bool")
    return {
        "namespace_used": bool(
            isolation["require_network_namespace"]
            or isolation["require_mount_namespace"]
        ),
        "seccomp_loaded": isolation["require_seccomp"],
        "cgroups_used": bool(
            mode == "full-root" and isolation["full_root_requires_cgroups"]
        ),
        "mlock_used": bool(
            mode == "full-root" and isolation["full_root_requires_mlock"]
        ),
    }


def _validate_finding_list(value: Any, *, receipt_form: bool) -> list[tuple[str, int, str]]:
    if not isinstance(value, list) or len(value) > 512:
        raise ValueError("browser finding list is invalid")
    identifier_key = "finding_id" if receipt_form else "rule_id"
    expected = {identifier_key, "count", "severity"}
    normalized: list[tuple[str, int, str]] = []
    for finding in value:
        if not isinstance(finding, dict) or set(finding) != expected:
            raise ValueError("browser finding is malformed")
        identifier = finding[identifier_key]
        count = finding["count"]
        severity = finding["severity"]
        if (
            not isinstance(identifier, str)
            or not 1 <= len(identifier) <= 128
            or not isinstance(count, int)
            or isinstance(count, bool)
            or count < 1
            or severity not in {"HIGH", "CRITICAL"}
        ):
            raise ValueError("browser finding value is invalid")
        normalized.append((identifier, count, severity))
    if normalized != sorted(normalized) or len({item[0] for item in normalized}) != len(normalized):
        raise ValueError("browser findings must be sorted and unique")
    return normalized


def _validate_stream_status(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict) or set(value) != set(BROWSER_STREAMS):
        raise ValueError("browser stream status set is invalid")
    normalized: dict[str, dict[str, Any]] = {}
    for source in BROWSER_STREAMS:
        status = value[source]
        if (
            not isinstance(status, dict)
            or set(status) != {"complete", "event_count", "observed_event_count"}
            or not isinstance(status.get("complete"), bool)
            or not _bounded_uint(status.get("event_count"))
            or not _bounded_uint(status.get("observed_event_count"))
        ):
            raise ValueError("browser stream status is malformed")
        normalized[source] = status
    return normalized


def _validate_browser_probe_section(receipt: dict) -> None:
    """Validate and cross-bind every signed browser-probe receipt section."""

    identity = receipt["identity"]
    if (
        not isinstance(identity, dict)
        or set(identity)
        != {"job_id", "artifact_sha256", "artifact_type", "submitted_by", "received_at"}
        or identity.get("artifact_type") != "browser-probe"
        or not isinstance(identity.get("job_id"), str)
        or _BROWSER_JOB_ID.fullmatch(identity["job_id"]) is None
        or not isinstance(identity.get("submitted_by"), str)
        or not 1 <= len(identity["submitted_by"]) <= 256
        or not isinstance(identity.get("received_at"), str)
        or not 1 <= len(identity["received_at"]) <= 128
    ):
        raise ValueError("browser receipt identity is malformed")

    snapshot = receipt["snapshot_policy"]
    if (
        not isinstance(snapshot, dict)
        or set(snapshot)
        != {
            "snapshot_sha256",
            "snapshot_verified_by",
            "policy_version",
            "policy_hash",
            "memory_snapshots",
        }
        or not _is_sha256(snapshot.get("snapshot_sha256"))
        or not _is_sha256(snapshot.get("policy_hash"))
        or snapshot.get("memory_snapshots") != "disabled-v1"
        or not isinstance(snapshot.get("snapshot_verified_by"), str)
        or not 1 <= len(snapshot["snapshot_verified_by"]) <= 512
        or not isinstance(snapshot.get("policy_version"), str)
        or not 1 <= len(snapshot["policy_version"]) <= 128
    ):
        raise ValueError("browser snapshot policy is malformed")

    budgets = receipt["budgets_granted"]
    if not isinstance(budgets, dict) or set(budgets) != _BROWSER_BUDGET_KEYS:
        raise ValueError("browser granted budgets are malformed")
    budget_ranges = {
        "wall_clock_sec": (1, 60),
        "cpu_vcpu": (1, 2),
        "ram_mib": (256, 4096),
        "max_network_bytes": (1, 64 * 1024 * 1024),
        "max_events": (1, MAX_EVIDENCE_EVENTS),
        "max_redirects": (0, 20),
    }
    for name, (minimum, maximum) in budget_ranges.items():
        value = budgets[name]
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not minimum <= value <= maximum
        ):
            raise ValueError("browser granted budget is invalid")
    if (
        budgets["max_tabs"] != 1
        or budgets["interaction"] != "passive navigation only"
        or budgets["fs_writes"] != "guest tmpfs only"
    ):
        raise ValueError("browser granted capability budget is invalid")

    browser = receipt.get("browser_probe")
    if not isinstance(browser, dict) or set(browser) != _BROWSER_RECEIPT_KEYS:
        raise ValueError("browser-probe artifacts require a complete browser probe section")
    if browser["schema_version"] != "cindermote.browser-probe-receipt/v2":
        raise ValueError("invalid browser probe receipt version")

    probe_input = browser["input"]
    if not isinstance(probe_input, dict) or set(probe_input) != _BROWSER_INPUT_KEYS:
        raise ValueError("browser probe input binding is malformed")
    if (
        probe_input["contract_version"] != BROWSER_CONTRACT_VERSION
        or probe_input["navigation_mode"] != "passive"
        or not _is_sha256(probe_input["url_sha256"])
        or not _is_sha256(probe_input["request_sha256"])
        or not _is_sha256(probe_input["policy_hash"])
    ):
        raise ValueError("browser probe input binding is invalid")
    origins = probe_input["authorized_origins"]
    if (
        not isinstance(origins, list)
        or not 1 <= len(origins) <= MAX_AUTHORIZED_ORIGINS
        or any(not isinstance(origin, str) for origin in origins)
    ):
        raise ValueError("browser probe authorized origins are invalid")
    try:
        canonical_origins = [normalize_origin(origin) for origin in origins]
        initial_origin = normalize_origin(probe_input["normalized_origin"])
    except Exception as exc:
        raise ValueError("browser probe origin binding is invalid") from exc
    if origins != sorted(canonical_origins) or len(set(origins)) != len(origins):
        raise ValueError("browser probe authorized origins are not canonical")
    if initial_origin != probe_input["normalized_origin"] or initial_origin not in origins:
        raise ValueError("browser probe initial origin is not authorized")

    runtime = browser["runtime"]
    if (
        not isinstance(runtime, dict)
        or not _BROWSER_RUNTIME_BASE_KEYS.issubset(runtime)
        or set(runtime) - _BROWSER_RUNTIME_BASE_KEYS - _BROWSER_RUNTIME_OPTIONAL_KEYS
    ):
        raise ValueError("browser runtime identity is incomplete")
    if not isinstance(runtime["admitted"], bool):
        raise ValueError("browser runtime admission must be bool")
    for name in (
        "firecracker_sha256",
        "jailer_sha256",
        "kernel_sha256",
        "rootfs_sha256",
        "rootfs_receipt_sha256",
        "browser_sha256",
    ):
        if not _is_sha256(runtime[name]):
            raise ValueError(f"browser runtime {name} is invalid")
    for name in (
        "host_runtime_tmpfs",
        "host_swap_disabled",
        "rootfs_read_only",
        "guest_writes_tmpfs_only",
        "mmds_enabled",
    ):
        if not isinstance(runtime[name], bool):
            raise ValueError(f"browser runtime {name} must be bool")
    if (
        not isinstance(runtime["firecracker_version"], str)
        or not 1 <= len(runtime["firecracker_version"]) <= 128
        or not isinstance(runtime["browser_version"], str)
        or not 1 <= len(runtime["browser_version"]) <= 512
        or runtime["network_mode"] != "explicit-proxy-only"
        or runtime["mmds_enabled"] is not False
    ):
        raise ValueError("browser runtime identity is invalid")
    vmm_identity = runtime["vmm_identity"]
    if (
        not isinstance(vmm_identity, dict)
        or set(vmm_identity) != {"user", "group", "uid", "gid"}
        or vmm_identity.get("user") != "cindermote-vmm"
        or vmm_identity.get("group") != "cindermote-vmm"
        or not isinstance(vmm_identity.get("uid"), int)
        or isinstance(vmm_identity.get("uid"), bool)
        or not isinstance(vmm_identity.get("gid"), int)
        or isinstance(vmm_identity.get("gid"), bool)
        or not 0 < vmm_identity["uid"] < 2**31
        or not 0 < vmm_identity["gid"] < 2**31
        or vmm_identity["uid"] in {0, 65533, 65534}
        or vmm_identity["gid"] in {0, 65533, 65534}
    ):
        raise ValueError("browser VMM identity receipt is invalid")
    if "vmm_exit_code" in runtime and (
        runtime["vmm_exit_code"] is not None
        and (
            not isinstance(runtime["vmm_exit_code"], int)
            or isinstance(runtime["vmm_exit_code"], bool)
            or not -255 <= runtime["vmm_exit_code"] <= 255
        )
    ):
        raise ValueError("browser VMM exit status is invalid")
    if "cgroup_limits" in runtime:
        limits = runtime["cgroup_limits"]
        if (
            not isinstance(limits, dict)
            or set(limits) - {"cpu.max", "memory.max", "memory.swap.max", "pids.max"}
            or any(
                not isinstance(value, str) or not 1 <= len(value) <= 128
                for value in limits.values()
            )
        ):
            raise ValueError("browser cgroup readback is invalid")
    if runtime["admitted"]:
        if not _is_sha256(runtime.get("job_image_sha256")):
            raise ValueError("admitted browser runtime lacks job image identity")
        expected_cgroup_limits = {
            "cpu.max": f"{100000 * budgets['cpu_vcpu']} 100000",
            "memory.max": str((budgets["ram_mib"] + 512) * 1024 * 1024),
            "memory.swap.max": "0",
            "pids.max": "256",
        }
        if runtime.get("cgroup_limits") != expected_cgroup_limits:
            raise ValueError("admitted browser runtime lacks exact cgroup readback")
        if not all(
            runtime[name]
            for name in (
                "host_runtime_tmpfs",
                "host_swap_disabled",
                "rootfs_read_only",
                "guest_writes_tmpfs_only",
            )
        ):
            raise ValueError("admitted browser runtime lacks mandatory isolation")
        worker = runtime.get("egress_worker")
        if (
            not isinstance(worker, dict)
            or set(worker)
            != {
                "privilege_separated",
                "protocol_version",
                "user",
                "group",
                "uid",
                "gid",
                "no_new_privs",
                "dumpable",
                "capabilities_zero",
            }
            or worker.get("privilege_separated") is not True
            or worker.get("protocol_version") != "cindermote.browser-egress-worker/v2"
            or worker.get("user") != "cindermote-proxy"
            or worker.get("group") != "cindermote-proxy"
            or not isinstance(worker.get("uid"), int)
            or isinstance(worker.get("uid"), bool)
            or not isinstance(worker.get("gid"), int)
            or isinstance(worker.get("gid"), bool)
            or not 0 < worker["uid"] < 2**31
            or not 0 < worker["gid"] < 2**31
            or worker["uid"] in {65533, 65534}
            or worker["gid"] in {65533, 65534}
            or {worker["uid"], worker["gid"]}
            & {vmm_identity["uid"], vmm_identity["gid"]}
            or worker.get("no_new_privs") is not True
            or worker.get("dumpable") not in {0, False}
            or worker.get("capabilities_zero") is not True
        ):
            raise ValueError("admitted browser runtime lacks worker confinement receipt")
        supervision = runtime.get("jailer_supervision")
        if (
            not isinstance(supervision, dict)
            or supervision
            != {
                "external_supervisor": True,
                "parent_death_signal": "SIGTERM",
                "vmm_process_group_kill": "SIGKILL",
                "startup_reconciliation": "exact-owned-prefix",
            }
        ):
            raise ValueError("admitted browser runtime lacks parent-death supervision")

    evidence = browser["evidence"]
    if not isinstance(evidence, dict) or set(evidence) != _BROWSER_EVIDENCE_KEYS:
        raise ValueError("browser evidence commitment is malformed")
    if (
        evidence["schema_version"] != BROWSER_EVIDENCE_VERSION
        or not _is_sha256(evidence["sha256"])
        or not _bounded_uint(evidence["events_observed"])
    ):
        raise ValueError("browser evidence commitment is invalid")
    stream_status = _validate_stream_status(evidence["stream_status"])
    if (
        sum(status["observed_event_count"] for status in stream_status.values())
        != evidence["events_observed"]
    ):
        raise ValueError("browser evidence stream counts do not match total")

    reduction = browser["reduction"]
    if not isinstance(reduction, dict) or set(reduction) != _BROWSER_REDUCTION_KEYS:
        raise ValueError("browser evidence reduction is malformed")
    if (
        reduction["evidence_version"] != BROWSER_EVIDENCE_VERSION
        or reduction["decision"] not in {"ALLOW", "DENY"}
        or not _bounded_uint(reduction["events_observed"])
        or any(
            not isinstance(reduction[name], bool)
            for name in ("complete", "telemetry_incomplete", "fail_closed")
        )
        or reduction["events_observed"] != evidence["events_observed"]
        or reduction["fail_closed"] != reduction["telemetry_incomplete"]
        or reduction["complete"] == reduction["telemetry_incomplete"]
        or (reduction["telemetry_incomplete"] and reduction["decision"] != "DENY")
    ):
        raise ValueError("browser evidence reduction is inconsistent")
    reduction_streams = reduction["streams"]
    if not isinstance(reduction_streams, dict) or set(reduction_streams) != set(BROWSER_STREAMS):
        raise ValueError("browser reduction stream set is invalid")
    observed_total = 0
    for source in BROWSER_STREAMS:
        status = reduction_streams[source]
        if (
            not isinstance(status, dict)
            or set(status) != {
                "declared_event_count",
                "observed_event_count",
                "complete",
            }
            or not _bounded_uint(status.get("declared_event_count"))
            or not _bounded_uint(status.get("observed_event_count"))
            or not isinstance(status.get("complete"), bool)
            or status["declared_event_count"] != stream_status[source]["event_count"]
            or status["observed_event_count"]
            != stream_status[source]["observed_event_count"]
            or status["complete"] != stream_status[source]["complete"]
        ):
            raise ValueError("browser reduction stream is inconsistent")
        observed_total += status["observed_event_count"]
    if observed_total != evidence["events_observed"]:
        raise ValueError("browser reduction observed counts do not match total")
    reduction_findings = _validate_finding_list(reduction["findings"], receipt_form=True)
    reduction_finding_counts = {
        identifier: count for identifier, count, _severity in reduction_findings
    }
    mismatch_count = sum(
        status["declared_event_count"] != status["observed_event_count"]
        for status in reduction_streams.values()
    )
    if reduction_finding_counts.get("web_evidence_count_mismatch", 0) != mismatch_count:
        raise ValueError("browser evidence count mismatch finding is inconsistent")
    expected_reduction_incomplete = any(
        not status["complete"] for status in reduction_streams.values()
    ) or any(
        identifier in TELEMETRY_INCOMPLETE_FINDINGS
        for identifier, _count, _severity in reduction_findings
    )
    if (
        reduction["telemetry_incomplete"] != expected_reduction_incomplete
        or reduction["complete"] == expected_reduction_incomplete
        or reduction["fail_closed"] != expected_reduction_incomplete
    ):
        raise ValueError("browser reduction completeness is not evidence-derived")
    for identifier, _count, severity in reduction_findings:
        if identifier not in RULES or RULES[identifier][1] != severity or not identifier.startswith("web_"):
            raise ValueError("browser reduction finding is not a canonical browser rule")
    if reduction["decision"] != ("DENY" if reduction_findings else "ALLOW"):
        raise ValueError("browser reduction decision does not match its findings")

    artifacts = browser["artifacts"]
    if not isinstance(artifacts, dict) or artifacts.get("raw_retained") is not False:
        raise ValueError("browser artifacts must be metadata-only")
    if set(artifacts) == _BROWSER_ARTIFACT_KEYS:
        if not isinstance(artifacts["attestation_complete"], bool):
            raise ValueError("browser artifact attestation status is invalid")
        for name in ("dom_sha256", "visible_text_sha256", "screenshot_sha256"):
            if not _is_sha256(artifacts[name]):
                raise ValueError("browser artifact digest is invalid")
        if not _bounded_uint(artifacts["console_event_count"]):
            raise ValueError("browser console event count is invalid")
    elif set(artifacts) != {"raw_retained"} or runtime["admitted"]:
        raise ValueError("failed browser artifacts have an unexpected shape")

    browser_findings = _validate_finding_list(browser["findings"], receipt_form=True)
    detector_findings = _validate_finding_list(receipt["detector_findings"], receipt_form=False)
    if browser_findings != detector_findings:
        raise ValueError("browser findings are not bound to detector findings")
    browser_finding_map = {identifier: (count, severity) for identifier, count, severity in browser_findings}

    purge = receipt["purge"]
    if not isinstance(purge, dict) or set(purge) != _BROWSER_PURGE_KEYS:
        raise ValueError("browser purge attestation is malformed")
    if any(not isinstance(purge[name], bool) for name in _BROWSER_PURGE_KEYS):
        raise ValueError("browser purge attestations must be bool")
    purge_components = _BROWSER_PURGE_KEYS - {"verified_externally"}
    if purge["verified_externally"] != all(purge[name] for name in purge_components):
        raise ValueError("browser aggregate purge attestation is inconsistent")
    expected_findings = {
        identifier: (count, severity)
        for identifier, count, severity in reduction_findings
    }
    if not runtime["admitted"]:
        expected_findings["firecracker_runtime_failure"] = (1, "CRITICAL")
    if not purge["verified_externally"]:
        expected_findings["purge_failure"] = (1, "CRITICAL")
    if browser_finding_map != expected_findings:
        raise ValueError("browser findings are not exactly bound to reduction/runtime/purge")
    if (
        set(artifacts) == _BROWSER_ARTIFACT_KEYS
        and artifacts["attestation_complete"] is False
        and (
            "web_cdp_telemetry_loss" not in expected_findings
            or reduction["telemetry_incomplete"] is not True
            or reduction["decision"] != "DENY"
        )
    ):
        raise ValueError("incomplete page attestation lacks fail-closed evidence")

    isolation = receipt["isolation"]
    required_isolation = {
        "mode",
        "namespace_used",
        "seccomp_loaded",
        "cgroups_used",
        "mlock_used",
        "jailer_used",
        "kvm_used",
        "host_runtime_tmpfs",
        "host_swap_disabled",
        "rootfs_read_only",
        "guest_writes_tmpfs_only",
    }
    if not isinstance(isolation, dict) or set(isolation) != required_isolation:
        raise ValueError("browser isolation receipt is malformed")
    if isolation["mode"] != "firecracker" or isolation["mlock_used"] is not False:
        raise ValueError("browser isolation mode is invalid")
    for name in required_isolation - {"mode"}:
        if not isinstance(isolation[name], bool):
            raise ValueError("browser isolation controls must be bool")
    for name in ("namespace_used", "seccomp_loaded", "cgroups_used", "jailer_used", "kvm_used"):
        if isolation[name] != runtime["admitted"]:
            raise ValueError("browser admission and isolation receipt disagree")
    for name in (
        "host_runtime_tmpfs",
        "host_swap_disabled",
        "rootfs_read_only",
        "guest_writes_tmpfs_only",
    ):
        if isolation[name] != runtime[name]:
            raise ValueError("browser runtime and isolation receipt disagree")

    if snapshot["snapshot_sha256"] != runtime["rootfs_sha256"]:
        raise ValueError("browser rootfs is not bound to snapshot policy")
    if snapshot["policy_hash"] != probe_input["policy_hash"]:
        raise ValueError("browser policy hashes disagree")
    capabilities = receipt["capabilities"]
    binding = capabilities.get("binding") if isinstance(capabilities, dict) else None
    if (
        not isinstance(capabilities, dict)
        or set(capabilities) != {"requested", "granted", "denied", "binding"}
        or capabilities.get("requested") != ["browser.navigate"]
        or capabilities.get("granted") != ["browser.navigate"]
        or capabilities.get("denied")
        != ["browser.click", "browser.type", "browser.upload", "browser.download"]
        or not isinstance(binding, dict)
        or set(binding) != {"request_sha256", "job_id"}
        or binding.get("request_sha256") != probe_input["request_sha256"]
        or binding.get("job_id") != identity["job_id"]
    ):
        raise ValueError("browser capability grant is not request-bound")
    max_events = budgets["max_events"]
    if (
        not _bounded_uint(max_events)
        or max_events < 1
        or (
            runtime["admitted"]
            and browser["artifacts"]["console_event_count"] > max_events
        )
    ):
        raise ValueError("browser receipt exceeds its admitted event budget")
    telemetry = receipt["telemetry_summary"]
    if (
        not isinstance(telemetry, dict)
        or set(telemetry) != {"events_observed", "streams", "metadata_only"}
        or telemetry.get("metadata_only") is not True
        or telemetry.get("events_observed") != evidence["events_observed"]
        or telemetry.get("streams") != stream_status
    ):
        raise ValueError("browser telemetry summary is not evidence-bound")
    if receipt["canaries_touched"] != {}:
        raise ValueError("browser profile cannot emit legacy canary content")
    gate = receipt["gate"]
    gate_keys = {
        "policy_gate_decision",
        "policy_gate_reason",
        "human_gate_override",
        "final_decision",
        "final_authority",
        "override_blocked_by_fail_closed",
    }
    if (
        not isinstance(gate, dict)
        or set(gate) != gate_keys
        or gate.get("policy_gate_decision") != reduction["decision"]
        or gate.get("policy_gate_reason") not in {
            "known_bad_behavior_detected",
            "canary_credential_accessed",
            "network_egress_attempted",
            "repeated_sandbox_probing",
            "anomalous_behavior_pattern",
            "bounded_browser_navigation_clean",
            "uncertain_classification",
        }
        or gate.get("human_gate_override") not in {"none", "ALLOW", "DENY"}
        or gate.get("final_decision") not in {"ALLOW", "DENY"}
        or gate.get("final_authority") not in {
            "fail_closed_infrastructure_gate",
            "human_gate_override",
            "policy_gate_autonomous",
        }
        or not isinstance(gate.get("override_blocked_by_fail_closed"), bool)
    ):
        raise ValueError("browser reduction and policy decision disagree")
    outward = receipt["outward_report"]
    expected_outward_evidence = [
        {
            "tap_category": RULES[identifier][0],
            "rule_id": identifier,
            "count": count,
        }
        for identifier, (count, _severity) in sorted(expected_findings.items())
    ]
    expected_risk = (
        "hostile"
        if any(severity == "CRITICAL" for _identifier, _count, severity in browser_findings)
        else "suspicious" if browser_findings else "benign"
    )
    destinations = receipt["destinations_attempted"]
    if not isinstance(destinations, dict) or len(destinations) > 256:
        raise ValueError("browser destination summary is malformed")
    for destination, labels in destinations.items():
        if (
            not isinstance(labels, list)
            or not 1 <= len(labels) <= len(_BROWSER_DESTINATION_LABELS)
            or labels != sorted(set(labels))
            or not set(labels).issubset(_BROWSER_DESTINATION_LABELS)
        ):
            raise ValueError("browser destination disposition is malformed")
        label_set = set(labels)
        connect_labels = label_set & _BROWSER_CONNECT_LABELS
        origin_labels = label_set & (
            _BROWSER_HTTP_ORIGIN_LABELS | _BROWSER_CDP_ORIGIN_LABELS
        )
        if connect_labels and origin_labels:
            raise ValueError("browser destination interchanges witness types")
        if connect_labels:
            try:
                canonical_destination = normalize_connect_authority(destination)
            except Exception as exc:
                raise ValueError(
                    "browser CONNECT destination is not a canonical authority"
                ) from exc
        else:
            try:
                canonical_destination = normalize_origin(destination)
            except Exception as exc:
                raise ValueError(
                    "browser web destination is not a canonical origin"
                ) from exc
            if (
                label_set & _BROWSER_HTTP_ORIGIN_LABELS
                and not canonical_destination.startswith("http://")
            ):
                raise ValueError(
                    "proxy HTTP-origin witness cannot claim an HTTPS origin"
                )
        if canonical_destination != destination:
            raise ValueError("browser destination witness is not canonical")
    if (
        outward["evidence"] != expected_outward_evidence
        or outward["risk_level"] != expected_risk
        or outward["capabilities_requested"] != ["browser.navigate"]
        or outward["destinations"] != sorted(destinations)
        or outward["canaries_tripped"] != []
        or outward["uncertainty"] != receipt["residual_uncertainty"]
    ):
        raise ValueError("browser outward report is not finding-bound")
    expected_budget_exhausted = bool(
        {"web_event_budget_exceeded", "web_redirect_budget_exceeded"}
        & set(browser_finding_map)
    )
    if receipt["budget_exhausted"] != expected_budget_exhausted:
        raise ValueError("browser budget exhaustion flag is inconsistent")
    expected_incomplete = reduction["telemetry_incomplete"] or not purge["verified_externally"]
    if receipt["telemetry_incomplete"] != expected_incomplete:
        raise ValueError("browser telemetry completeness is inconsistent")
    fail_closed_rules = bool(set(expected_findings) & UNOVERRIDABLE_RULES)
    human_override = gate["human_gate_override"]
    if fail_closed_rules:
        expected_final = "DENY"
        expected_authority = "fail_closed_infrastructure_gate"
    elif human_override in {"ALLOW", "DENY"}:
        expected_final = human_override
        expected_authority = "human_gate_override"
    else:
        expected_final = reduction["decision"]
        expected_authority = "policy_gate_autonomous"
    if (
        gate["final_decision"] != expected_final
        or gate["final_authority"] != expected_authority
        or gate["override_blocked_by_fail_closed"]
        != bool(fail_closed_rules and human_override == "ALLOW")
    ):
        raise ValueError("browser final gate authority is inconsistent")
    if not runtime["admitted"] or not purge["verified_externally"]:
        if gate.get("final_decision") != "DENY":
            raise ValueError("unadmitted or unpurged browser run must be denied")
    if gate.get("final_decision") == "ALLOW" and (
        not runtime["admitted"]
        or not purge["verified_externally"]
        or reduction["telemetry_incomplete"]
    ):
        raise ValueError("browser ALLOW lacks complete runtime evidence")


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_or_create_key(path: str | Path) -> bytes:
    key_path = Path(path)
    try:
        key = key_path.read_bytes()
    except FileNotFoundError:
        key_path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        descriptor = os.open(key_path, flags, 0o600)
        try:
            key = os.urandom(32)
            os.write(descriptor, key)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    if len(key) != 32:
        raise ValueError("observer key must contain exactly 32 bytes")
    os.chmod(key_path, 0o600)
    return key


def sign_receipt(receipt_without_signature: dict, key: bytes) -> str:
    return hmac.new(key, canonical_json(receipt_without_signature), hashlib.sha256).hexdigest()


def verify_signature(receipt: dict, key: bytes) -> bool:
    candidate = dict(receipt)
    signature = candidate.pop("receipt_signature", "")
    if not isinstance(signature, str):
        return False
    expected = sign_receipt(candidate, key)
    return hmac.compare_digest(signature, expected)


def _legacy_finding_map(value: Any) -> dict[str, tuple[int, str]]:
    if not isinstance(value, list) or len(value) > 512:
        raise ValueError("legacy detector findings must be a bounded list")
    normalized: dict[str, tuple[int, str]] = {}
    previous = ""
    for finding in value:
        if not isinstance(finding, dict) or set(finding) != {"rule_id", "count", "severity"}:
            raise ValueError("legacy detector finding is malformed")
        rule_id = finding["rule_id"]
        count = finding["count"]
        severity = finding["severity"]
        if (
            not isinstance(rule_id, str)
            or rule_id not in RULES
            or rule_id <= previous
            or not isinstance(count, int)
            or isinstance(count, bool)
            or count < 1
            or severity != RULES[rule_id][1]
        ):
            raise ValueError("legacy detector finding is non-canonical")
        normalized[rule_id] = (count, severity)
        previous = rule_id
    return normalized


def _validate_legacy_receipt(
    receipt: dict,
    active_policy: str | Path | dict | None,
) -> None:
    policy = _load_active_policy(active_policy)
    snapshot = receipt["snapshot_policy"]
    if (
        not isinstance(snapshot, dict)
        or not _is_sha256(snapshot.get("policy_hash"))
        or snapshot["policy_hash"] != _canonical_hash(policy)
    ):
        raise ValueError("legacy receipt is not bound to the active policy")

    isolation = receipt["isolation"]
    if not isinstance(isolation, dict) or set(isolation) != _LEGACY_ISOLATION_KEYS:
        raise ValueError("legacy isolation receipt is malformed")
    mode = isolation["mode"]
    required_controls = required_isolation_controls(mode, policy)
    for name in required_controls:
        if not isinstance(isolation[name], bool):
            raise ValueError(f"isolation.{name} must be bool")
    missing_controls = sorted(
        name
        for name, required in required_controls.items()
        if required and not isolation[name]
    )

    purge = receipt["purge"]
    if not isinstance(purge, dict) or set(purge) != _LEGACY_PURGE_KEYS:
        raise ValueError("legacy purge result is malformed")
    if not isinstance(purge["method"], str) or not purge["method"]:
        raise ValueError("legacy purge method is invalid")
    purge_checks = (
        "verified_externally",
        "process_group_empty",
        "cgroup_empty",
        "cgroup_removed",
        "job_mount_removed",
        "job_directory_removed",
    )
    if any(not isinstance(purge[name], bool) for name in purge_checks):
        raise ValueError("legacy purge postconditions must be bool")
    processes_remaining = purge["processes_remaining"]
    resources = purge["remaining_host_resources"]
    if (
        not isinstance(processes_remaining, int)
        or isinstance(processes_remaining, bool)
        or processes_remaining < 0
        or not isinstance(resources, list)
        or resources != sorted(set(resources))
        or len(resources) > 512
        or any(not isinstance(item, str) or not item or len(item) > 1024 for item in resources)
    ):
        raise ValueError("legacy remaining-host-resource result is malformed")
    expected_purge = bool(
        purge["process_group_empty"]
        and purge["cgroup_empty"]
        and purge["cgroup_removed"]
        and purge["job_mount_removed"]
        and purge["job_directory_removed"]
        and processes_remaining == 0
        and not resources
    )
    if purge["verified_externally"] != expected_purge:
        raise ValueError("legacy aggregate purge result is inconsistent")

    finding_map = _legacy_finding_map(receipt["detector_findings"])
    purge_finding = finding_map.get("purge_failure")
    if purge["verified_externally"]:
        if purge_finding is not None:
            raise ValueError("verified legacy purge contradicts purge_failure")
    elif purge_finding != (1, "CRITICAL"):
        raise ValueError("failed legacy purge lacks canonical purge_failure")
    isolation_finding = finding_map.get("isolation_admission_failure")
    if isolation_finding is not None and isolation_finding != (1, "CRITICAL"):
        raise ValueError("legacy isolation admission failure is non-canonical")
    if missing_controls and isolation_finding != (1, "CRITICAL"):
        raise ValueError("missing required isolation lacks admission failure")

    outward = receipt["outward_report"]
    expected_evidence = [
        {
            "tap_category": RULES[rule_id][0],
            "rule_id": rule_id,
            "count": count,
        }
        for rule_id, (count, _severity) in finding_map.items()
    ]
    expected_risk = (
        "hostile"
        if any(RULES[rule_id][2] == "known_bad" for rule_id in finding_map)
        else "suspicious" if finding_map else "benign"
    )
    capabilities = receipt["capabilities"]
    requested = capabilities.get("requested") if isinstance(capabilities, dict) else None
    if (
        outward["evidence"] != expected_evidence
        or outward["risk_level"] != expected_risk
        or outward["capabilities_requested"] != requested
        or outward["uncertainty"] != receipt["residual_uncertainty"]
    ):
        raise ValueError("legacy outward report is not evidence-bound")

    gate = receipt["gate"]
    if not isinstance(gate, dict) or set(gate) != _LEGACY_GATE_KEYS:
        raise ValueError("legacy gate result is malformed")
    human_override = gate["human_gate_override"]
    if human_override not in {"none", "ALLOW", "DENY"}:
        raise ValueError("legacy human override is invalid")
    job_id = receipt["identity"].get("job_id")
    if not isinstance(job_id, str) or not job_id:
        raise ValueError("legacy job identity is invalid")
    overrides = {} if human_override == "none" else {job_id: human_override}
    expected_gate = apply_scoring_matrix(outward, overrides, job_id)
    if gate != expected_gate:
        raise ValueError("legacy gate result contradicts signed evidence")

    infrastructure_failed = bool(
        isolation_finding or missing_controls or not purge["verified_externally"]
    )
    if infrastructure_failed and receipt["telemetry_incomplete"] is not True:
        raise ValueError("legacy infrastructure failure must mark telemetry incomplete")
    if infrastructure_failed and receipt["residual_uncertainty"] != 1.0:
        raise ValueError("legacy infrastructure failure must retain full uncertainty")
    if gate["final_decision"] == "ALLOW" and (
        missing_controls or not purge["verified_externally"]
    ):
        raise ValueError("legacy ALLOW lacks required isolation or verified purge")


def validate_receipt(
    receipt: dict,
    *,
    active_policy: str | Path | dict | None = None,
) -> None:
    required = {
        "identity",
        "snapshot_policy",
        "isolation",
        "budgets_granted",
        "capabilities",
        "telemetry_summary",
        "canaries_touched",
        "destinations_attempted",
        "detector_findings",
        "gate",
        "outward_report",
        "purge",
        "telemetry_incomplete",
        "budget_exhausted",
        "residual_uncertainty",
        "receipt_signature",
    }
    optional = {"mcp_protocol", "browser_probe"}
    if not isinstance(receipt, dict) or not required.issubset(receipt):
        raise ValueError("receipt is missing required sections")
    if set(receipt) - required - optional:
        raise ValueError("receipt contains unknown sections")
    identity = receipt["identity"]
    if identity.get("artifact_type") not in ARTIFACT_TYPES:
        raise ValueError("invalid artifact type")
    if not _is_sha256(identity.get("artifact_sha256")):
        raise ValueError("invalid artifact hash")
    isolation = receipt["isolation"]
    if not isinstance(isolation, dict) or isolation.get("mode") not in {
        "full-root",
        "degraded-user",
        "firecracker",
    }:
        raise ValueError("invalid isolation mode")
    for key in ("namespace_used", "seccomp_loaded", "cgroups_used", "mlock_used"):
        if not isinstance(isolation.get(key), bool):
            raise ValueError(f"isolation.{key} must be bool")
    if receipt["gate"].get("final_decision") not in {"ALLOW", "DENY"}:
        raise ValueError("invalid final gate decision")
    if receipt["purge"].get("verified_externally") not in {True, False}:
        raise ValueError("purge verification must be bool")
    for name in ("telemetry_incomplete", "budget_exhausted"):
        if not isinstance(receipt[name], bool):
            raise ValueError(f"{name} must be bool")
    validate_outward_report(receipt["outward_report"])
    signature = receipt["receipt_signature"]
    if not _is_sha256(signature):
        raise ValueError("invalid receipt signature")
    is_browser = receipt["identity"].get("artifact_type") == "browser-probe"
    has_browser = "browser_probe" in receipt
    if is_browser != has_browser:
        raise ValueError("browser probe section must exist iff artifact type is browser-probe")
    if is_browser:
        _validate_browser_probe_section(receipt)
    else:
        _validate_legacy_receipt(receipt, active_policy)


def create_receipt(
    *,
    identity: dict,
    snapshot_policy: dict,
    isolation: dict,
    budgets_granted: dict,
    capabilities: dict,
    telemetry_summary: dict,
    canaries_touched: dict,
    destinations_attempted: dict,
    detector_findings: list[dict],
    gate: dict,
    outward_report: dict,
    purge: dict,
    telemetry_incomplete: bool,
    budget_exhausted: bool,
    residual_uncertainty: float,
    key_path: str | Path,
    mcp_protocol: dict | None = None,
    browser_probe: dict | None = None,
    active_policy: str | Path | dict | None = None,
) -> dict:
    unsigned = {
        "identity": identity,
        "snapshot_policy": snapshot_policy,
        "isolation": isolation,
        "budgets_granted": budgets_granted,
        "capabilities": capabilities,
        "telemetry_summary": telemetry_summary,
        "canaries_touched": canaries_touched,
        "destinations_attempted": destinations_attempted,
        "detector_findings": detector_findings,
        "gate": gate,
        "outward_report": outward_report,
        "purge": purge,
        # These flags are required by the failure-mode section even though the
        # abbreviated receipt example does not display them.
        "telemetry_incomplete": bool(telemetry_incomplete),
        "budget_exhausted": bool(budget_exhausted),
        "residual_uncertainty": max(0.0, min(1.0, float(residual_uncertainty))),
    }
    if mcp_protocol is not None:
        unsigned["mcp_protocol"] = mcp_protocol
    if browser_probe is not None:
        unsigned["browser_probe"] = browser_probe
    key = load_or_create_key(key_path)
    receipt = dict(unsigned)
    receipt["receipt_signature"] = sign_receipt(unsigned, key)
    validate_receipt(receipt, active_policy=active_policy)
    return receipt


def write_receipt(
    path: str | Path,
    receipt: dict,
    *,
    active_policy: str | Path | dict | None = None,
) -> None:
    validate_receipt(receipt, active_policy=active_policy)
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    payload = json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(descriptor, payload.encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, destination)
