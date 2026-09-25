"""Top-level bounded agent-probe v0 orchestration."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from cindermote.mote.firecracker_runtime import FirecrackerUnavailable

from .canonical import canonical_bytes, sha256_hex
from .contract import ModelConfig, build_job_manifest, build_road_frozen, sign_envelope
from .firecracker_runtime import AgentProbeRuntimeResult, run_agent_probe_microvm
from .ksl import build_host_lifecycle, build_road_diff, build_road_walked
from .receipt import build_receipt_envelope, derive_exit_code

PROJECT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_OBSERVER_KEY = PROJECT_DIR / ".observer_key"
DEFAULT_QUARANTINE_PUBLIC_KEY = PROJECT_DIR / "policy" / "agent-probe-quarantine.x25519.pub"
DEFAULT_QUARANTINE_DIR = PROJECT_DIR / "quarantine" / "agent-probe"
DEFAULT_RECEIPT_DIR = PROJECT_DIR / "receipts" / "agent-probe"


class AgentProbeError(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentProbeRun:
    envelope: dict[str, Any]
    exit_code: int
    job_id: str
    receipt_path: str
    road_frozen_path: str
    road_walked_path: str
    road_diff_path: str
    evidence_path: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope,
            "exit_code": self.exit_code,
            "job_id": self.job_id,
            "receipt_path": self.receipt_path,
            "road_frozen_path": self.road_frozen_path,
            "road_walked_path": self.road_walked_path,
            "road_diff_path": self.road_diff_path,
            "evidence_path": self.evidence_path,
        }


def _read_exact_key(path: Path, *, name: str, lengths: set[int]) -> bytes:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise AgentProbeError(f"{name} is unavailable") from exc
    if len(raw) in lengths:
        # Exact-length raw key material: accept as-is.  Stripping first
        # would corrupt random binary keys whose trailing byte is ASCII
        # whitespace.
        return bytes(raw)
    candidate = raw.strip()
    if len(candidate) in lengths:
        return bytes(candidate)
    try:
        decoded = bytes.fromhex(candidate.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        decoded = b""
    if len(decoded) in lengths:
        return decoded
    raise AgentProbeError(f"{name} has an invalid length")


def _write_private_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise AgentProbeError("receipt directory is unsafe")
    temporary = path.with_name(path.name + ".tmp")
    payload = canonical_bytes(value) + b"\n"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short private JSON write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)


def run_agent_probe(
    target_path: Path | str,
    *,
    model: ModelConfig,
    api_key: bytearray,
    observer_key: bytes | None = None,
    quarantine_public_key: bytes | None = None,
    quarantine_key_id: str | None = None,
    observer_key_path: Path | str = DEFAULT_OBSERVER_KEY,
    quarantine_public_key_path: Path | str = DEFAULT_QUARANTINE_PUBLIC_KEY,
    quarantine_dir: Path | str = DEFAULT_QUARANTINE_DIR,
    receipt_dir: Path | str = DEFAULT_RECEIPT_DIR,
    budgets: dict[str, int] | None = None,
    runtime: Callable[..., AgentProbeRuntimeResult] = run_agent_probe_microvm,
    runtime_kwargs: dict[str, Any] | None = None,
) -> AgentProbeRun:
    """Run one real Firecracker-only agent probe and persist bounded artifacts."""

    target = Path(target_path).resolve()
    if not target.is_file() or target.is_symlink():
        raise FileNotFoundError(target)
    target_bytes = target.read_bytes()  # Opaque host transport and hashing only.
    if len(target_bytes) > 1024 * 1024:
        raise AgentProbeError("target exceeds the v0 one-MiB limit")
    if not isinstance(api_key, bytearray) or not 1 <= len(api_key) <= 4096:
        raise AgentProbeError("fresh API credential is required as a mutable bytearray")

    signing_key = observer_key or _read_exact_key(
        Path(observer_key_path), name="observer signing key", lengths={32, 48, 64}
    )
    quarantine_key = quarantine_public_key or _read_exact_key(
        Path(quarantine_public_key_path), name="quarantine X25519 public key", lengths={32}
    )
    key_id = quarantine_key_id or sha256_hex({"x25519_public_key_hex": quarantine_key.hex()})[:32]

    manifest = build_job_manifest(
        target_bytes=target_bytes,
        model=model,
        quarantine_public_key=quarantine_key,
        quarantine_key_id=key_id,
        budgets=budgets,
    )
    road_frozen = build_road_frozen(manifest)
    road_frozen_hash = sha256_hex(road_frozen)
    road_frozen_envelope = sign_envelope(
        road_frozen, "cindermote.road-frozen/v1", signing_key
    )

    runtime_result: AgentProbeRuntimeResult | None = None
    admission_failed = False
    runtime_failure: dict[str, Any] | None = None
    try:
        runtime_result = runtime(
            manifest=manifest,
            road_frozen_hash=road_frozen_hash,
            target_bytes=target_bytes,
            api_key=api_key,
            quarantine_dir=quarantine_dir,
            **(runtime_kwargs or {}),
        )
    except FirecrackerUnavailable:
        admission_failed = True
    except OSError as exc:
        # Bounded metadata only: exception messages can carry host paths or
        # target-identifying text, which must not enter signed artifacts.
        runtime_failure = {
            "code": "RUNTIME_OSERROR",
            "exception": type(exc).__name__,
            "errno": exc.errno if isinstance(exc.errno, int) else None,
        }
    except Exception as exc:
        runtime_failure = {
            "code": "RUNTIME_UNEXPECTED_ERROR",
            "exception": type(exc).__name__,
            "errno": None,
        }
    finally:
        for index in range(len(api_key)):
            api_key[index] = 0

    host_lifecycle = build_host_lifecycle(
        job_id=manifest["job_id"],
        road_frozen_hash=road_frozen_hash,
        runtime_result=runtime_result,
        admission_failed_before_launch=admission_failed,
        runtime_failure=runtime_failure,
    )
    road_walked = build_road_walked(
        manifest=manifest,
        road_frozen_hash=road_frozen_hash,
        runtime_result=runtime_result,
        runtime_failure=runtime_failure,
    )
    road_diff = build_road_diff(
        manifest=manifest,
        road_frozen=road_frozen,
        road_walked=road_walked,
        host_lifecycle=host_lifecycle,
    )

    if runtime_result is None or runtime_result.guest_result is None:
        guest_evidence_manifest = {
            "guest_evidence_root": "0" * 64,
            "complete": False,
        }
    else:
        evidence_bundle = runtime_result.guest_result.get("evidence_bundle")
        guest_evidence_manifest = (
            evidence_bundle["manifest"]
            if isinstance(evidence_bundle, dict)
            else {"guest_evidence_root": "0" * 64, "complete": False}
        )

    cleanup_status = "VERIFIED" if host_lifecycle["cleanup_verified"] else "UNVERIFIED"
    runtime_failed = (
        admission_failed
        or runtime_result is None
        or runtime_result.failure_code != "NONE"
        or runtime_result.guest_result is None
    )
    execution_status = "INFRASTRUCTURE_FAILED" if runtime_failed else "COMPLETE"
    gate_decision = road_diff["gate_decision"]
    if execution_status == "INFRASTRUCTURE_FAILED":
        gate_decision = "EVALUATION_INCOMPLETE"

    receipt_envelope = build_receipt_envelope(
        job_manifest=manifest,
        road_frozen=road_frozen,
        road_walked=road_walked,
        road_diff=road_diff,
        guest_evidence_manifest=guest_evidence_manifest,
        host_lifecycle=host_lifecycle,
        execution_status=execution_status,
        gate_decision=gate_decision,
        cleanup_status=cleanup_status,
        observer_key=signing_key,
    )
    exit_code = derive_exit_code(receipt_envelope, signing_key)

    output_root = Path(receipt_dir).resolve()
    job_id = manifest["job_id"]
    road_frozen_path = output_root / f"{job_id}.road-frozen.json"
    road_walked_path = output_root / f"{job_id}.road-walked.json"
    road_diff_path = output_root / f"{job_id}.road-diff.json"
    receipt_path = output_root / f"{job_id}.receipt.json"
    _write_private_json(road_frozen_path, road_frozen_envelope)
    _write_private_json(road_walked_path, road_walked)
    _write_private_json(road_diff_path, road_diff)
    _write_private_json(receipt_path, receipt_envelope)

    return AgentProbeRun(
        envelope=receipt_envelope,
        exit_code=exit_code,
        job_id=job_id,
        receipt_path=str(receipt_path),
        road_frozen_path=str(road_frozen_path),
        road_walked_path=str(road_walked_path),
        road_diff_path=str(road_diff_path),
        evidence_path=runtime_result.evidence_path if runtime_result is not None else None,
    )


__all__ = ["AgentProbeError", "AgentProbeRun", "run_agent_probe"]
