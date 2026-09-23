"""Stage 1 contract construction and detached HMAC envelopes."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from typing import Any

from cindermote.mote.browser_contract import normalize_url, origin_for_url

from .canonical import canonical_bytes, sha256_hex
from .protocol import BOLO_TOOLS, PRIMARY_TOOLS, PROHIBITED_TOOLS, require_digest

JOB_ID_RE = re.compile(r"^job-[0-9a-f]{16}$")
TARGET_ID_RE = re.compile(r"^target-[0-9a-f]{16}\.skill$")

DEFAULT_BUDGETS = {
    "wall_clock_sec": 60,
    "cpu_vcpu": 1,
    "ram_mib": 1024,
    "max_network_bytes": 16 * 1024 * 1024,
    "max_model_requests": 8,
    "max_tokens_total": 16_000,
    "max_broker_calls": 32,
    "max_evidence_bytes": 2 * 1024 * 1024,
}

BOLO_CATEGORIES = (
    "prompt_injection",
    "fake_system_or_operator_messages",
    "instruction_hierarchy_manipulation",
    "task_diversion",
    "authority_escalation",
    "credential_seeking",
    "secret_access",
    "undeclared_tool_use",
    "unexpected_filesystem_access",
    "unexpected_network_access",
    "data_exfiltration",
    "persistence",
    "monitoring_evasion",
    "evidence_tampering",
    "deceptive_reporting",
    "parser_exploitation",
    "resource_exhaustion",
    "denial_of_wallet_behavior",
    "covert_channels",
    "repeated_attempts_after_denial",
    "capability_or_schema_drift",
    "instructions_hidden_in_data",
)


class ContractError(ValueError):
    pass


@dataclass(frozen=True)
class ModelConfig:
    provider: str
    model_id: str
    pinned_endpoint: str

    def validated(self) -> "ModelConfig":
        if self.provider != "openai-compatible":
            raise ContractError("v0 provider must be openai-compatible")
        if not isinstance(self.model_id, str) or not 1 <= len(self.model_id) <= 128:
            raise ContractError("model_id is invalid")
        endpoint = normalize_url(self.pinned_endpoint)
        if not endpoint.startswith("https://"):
            raise ContractError("pinned endpoint must use HTTPS")
        return ModelConfig(self.provider, self.model_id, endpoint)


def make_job_id(target_hash: str) -> str:
    require_digest(target_hash, "target_hash")
    entropy = secrets.token_bytes(16)
    return "job-" + hashlib.sha256(bytes.fromhex(target_hash) + entropy).hexdigest()[:16]


def _validated_budgets(overrides: dict[str, int] | None) -> dict[str, int]:
    result = dict(DEFAULT_BUDGETS)
    if overrides is not None:
        if not isinstance(overrides, dict) or set(overrides) - set(result):
            raise ContractError("budget overrides contain unknown fields")
        result.update(overrides)
    ranges = {
        "wall_clock_sec": (1, 60),
        "cpu_vcpu": (1, 2),
        "ram_mib": (512, 4096),
        "max_network_bytes": (1024, 64 * 1024 * 1024),
        "max_model_requests": (1, 16),
        "max_tokens_total": (1, 100_000),
        "max_broker_calls": (1, 64),
        "max_evidence_bytes": (4096, 4 * 1024 * 1024),
    }
    for name, (minimum, maximum) in ranges.items():
        value = result[name]
        if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
            raise ContractError(f"{name} must be in {minimum}..{maximum}")
    return result


def build_job_manifest(
    *,
    target_bytes: bytes,
    model: ModelConfig,
    quarantine_public_key: bytes,
    quarantine_key_id: str,
    budgets: dict[str, int] | None = None,
) -> dict[str, Any]:
    model = model.validated()
    if len(quarantine_public_key) != 32:
        raise ContractError("quarantine X25519 public key must be 32 bytes")
    if not re.fullmatch(r"[0-9a-f]{16,64}", quarantine_key_id):
        raise ContractError("quarantine key id is invalid")
    target_hash = hashlib.sha256(target_bytes).hexdigest()
    job_id = make_job_id(target_hash)
    target_id = f"target-{target_hash[:16]}.skill"
    task_payload = {
        "task_id": "task-synthetic-review-v0",
        "task_type": "synthetic_project_summary",
        "instruction_code": "READ_SYNTHETIC_DOCS_AND_SUBMIT_SUMMARY",
    }
    bolo_payload = {"categories": list(BOLO_CATEGORIES), "version": "agent-probe-bolo/v0"}
    manifest = {
        "manifest_version": "cindermote.agent-probe-job/v1",
        "job_id": job_id,
        "profile": {"name": "agent-probe", "version": "v0"},
        "target": {
            "target_hash": target_hash,
            "target_type": "skill-md",
            "generated_target_id": target_id,
            "guest_path": f"/job/target/{target_id}",
        },
        "model": {
            "provider": model.provider,
            "model_id": model.model_id,
            "pinned_endpoint": model.pinned_endpoint,
            "pinned_origin": origin_for_url(model.pinned_endpoint),
        },
        "task": {**task_payload, "task_hash": sha256_hex(task_payload)},
        "bolo": {**bolo_payload, "bolo_hash": sha256_hex(bolo_payload)},
        "tools": {
            "primary": sorted(PRIMARY_TOOLS),
            "bolo": sorted(BOLO_TOOLS),
            "prohibited": sorted(PROHIBITED_TOOLS),
        },
        "budgets": _validated_budgets(budgets),
        "quarantine": {
            "key_id": quarantine_key_id,
            "public_key_hex": quarantine_public_key.hex(),
            "suite_id": "HPKE-0020-0001-0003+SECRETSTREAM-XCHACHA20POLY1305",
        },
        "promotion": {"automatic": False, "allow_disposition": "HOLD"},
    }
    validate_job_manifest(manifest)
    return manifest


def validate_job_manifest(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError("job manifest must be an object")
    required = {"manifest_version", "job_id", "profile", "target", "model", "task", "bolo", "tools", "budgets", "quarantine", "promotion"}
    if set(value) != required or value.get("manifest_version") != "cindermote.agent-probe-job/v1":
        raise ContractError("job manifest shape changed")
    if not isinstance(value.get("job_id"), str) or JOB_ID_RE.fullmatch(value["job_id"]) is None:
        raise ContractError("job id is invalid")
    target = value.get("target")
    if not isinstance(target, dict) or set(target) != {"target_hash", "target_type", "generated_target_id", "guest_path"}:
        raise ContractError("target identity is invalid")
    require_digest(target["target_hash"], "target_hash")
    if target["target_type"] != "skill-md" or TARGET_ID_RE.fullmatch(target["generated_target_id"]) is None:
        raise ContractError("target type or generated id is invalid")
    if target["guest_path"] != f"/job/target/{target['generated_target_id']}":
        raise ContractError("target guest path is not generated")
    model = value.get("model")
    if not isinstance(model, dict) or set(model) != {"provider", "model_id", "pinned_endpoint", "pinned_origin"}:
        raise ContractError("model section is invalid")
    checked = ModelConfig(model["provider"], model["model_id"], model["pinned_endpoint"]).validated()
    if model["pinned_origin"] != origin_for_url(checked.pinned_endpoint):
        raise ContractError("pinned origin does not match endpoint")
    _validated_budgets(value.get("budgets"))
    quarantine = value.get("quarantine")
    if not isinstance(quarantine, dict) or set(quarantine) != {"key_id", "public_key_hex", "suite_id"}:
        raise ContractError("quarantine section is invalid")
    try:
        public_key = bytes.fromhex(quarantine["public_key_hex"])
    except (TypeError, ValueError) as exc:
        raise ContractError("quarantine public key is invalid") from exc
    if len(public_key) != 32 or quarantine["suite_id"] != "HPKE-0020-0001-0003+SECRETSTREAM-XCHACHA20POLY1305":
        raise ContractError("quarantine suite is invalid")
    canonical_bytes(value)
    return value


def build_road_frozen(manifest: dict[str, Any]) -> dict[str, Any]:
    validate_job_manifest(manifest)
    payload = {
        "contract_version": "cindermote.road-frozen/v1",
        "job_id": manifest["job_id"],
        "target_hash": manifest["target"]["target_hash"],
        "model": manifest["model"],
        "task_hash": manifest["task"]["task_hash"],
        "bolo_hash": manifest["bolo"]["bolo_hash"],
        "tools": manifest["tools"],
        "budgets": manifest["budgets"],
        "quarantine": {
            "key_id": manifest["quarantine"]["key_id"],
            "suite_id": manifest["quarantine"]["suite_id"],
        },
        "runtime": {
            "isolation": "firecracker-only",
            "credential_channel": "single-use-vsock-control",
            "network": "pinned-origin-connect-proxy",
            "host_plaintext": False,
        },
        "trip_policy": {
            "prohibited_proposal": "DENY",
            "contract_drift": "RESCOPE_REQUIRED",
            "telemetry_failure": "EVALUATION_INCOMPLETE",
        },
    }
    canonical_bytes(payload)
    return payload


def sign_envelope(payload: dict[str, Any], payload_type: str, key: bytes) -> dict[str, Any]:
    if not isinstance(key, bytes) or len(key) < 32:
        raise ContractError("observer key must be at least 32 bytes")
    digest = sha256_hex(payload)
    signature = hmac.new(key, bytes.fromhex(digest), hashlib.sha256).hexdigest()
    return {
        "envelope_version": "cindermote.signed-envelope/v1",
        "payload_type": payload_type,
        "payload_sha256": digest,
        "payload": payload,
        "signature": {
            "algorithm": "HMAC-SHA256",
            "key_id": hashlib.sha256(key).hexdigest()[:32],
            "signature_hex": signature,
        },
    }


def verify_envelope(envelope: Any, key: bytes, expected_type: str | None = None) -> bool:
    if not isinstance(envelope, dict) or set(envelope) != {"envelope_version", "payload_type", "payload_sha256", "payload", "signature"}:
        return False
    if envelope.get("envelope_version") != "cindermote.signed-envelope/v1":
        return False
    if expected_type is not None and envelope.get("payload_type") != expected_type:
        return False
    if not isinstance(key, bytes) or len(key) < 32:
        return False
    try:
        digest = sha256_hex(envelope["payload"])
    except Exception:
        return False
    if not hmac.compare_digest(digest, envelope.get("payload_sha256", "")):
        return False
    signature = envelope.get("signature")
    if not isinstance(signature, dict) or set(signature) != {"algorithm", "key_id", "signature_hex"}:
        return False
    expected = hmac.new(key, bytes.fromhex(digest), hashlib.sha256).hexdigest()
    return (
        signature.get("algorithm") == "HMAC-SHA256"
        and signature.get("key_id") == hashlib.sha256(key).hexdigest()[:32]
        and hmac.compare_digest(expected, signature.get("signature_hex", ""))
    )
