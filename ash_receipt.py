"""Cindermote Ash Receipt (Phase 8).

Defines the canonical, signed Ash Receipt emitted after Scalar Kernel
collapse, cinders, or teardown. Rejects default or hard-coded keys.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import secrets
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

PROHIBITED_STATIC_KEYS = {
    b"cindermote-observer-key-32bytes!",
    b"default_key",
    b"secret",
    b"password",
    b"12345678901234567890123456789012",
}


@dataclass
class AshReceipt:
    receipt_version: str = "cindermote-ash/v1"
    run_id: str = ""
    target_identity: str = ""
    target_hashes: Dict[str, str] = field(default_factory=dict)
    provenance: Dict[str, str] = field(
        default_factory=lambda: {
            "frozen_base_repo": "motefield (private predecessor)",
            "frozen_base_commit": "584ab11ea054efb233d057b64c342846ed201592",
        }
    )
    kernel_hash: str = "pinned-kernel-sha256"
    rootfs_hash: str = "pinned-rootfs-sha256"
    policy_hash: str = "policy-sha256"
    capability_manifest_hash: str = "manifest-sha256"
    seam_registry_hash: str = "seam-sha256"
    provider_id: str = "contained-relay/v1"
    model_id: str = "deepseek-chat"
    probe_profile: str = "full"
    mcp_protocol_version: str = "2024-11-05"
    discovered_surface_counts: Dict[str, int] = field(
        default_factory=lambda: {"tools": 0, "prompts": 0, "resources": 0}
    )
    discovered_surface_hashes: Dict[str, Any] = field(default_factory=dict)
    broker_events: List[Dict[str, Any]] = field(default_factory=list)
    collapse_cue: Optional[str] = None
    terminal_kind: str = "COLLAPSE"  # COLLAPSE, CINDER, NORMAL
    burn_steps: List[str] = field(
        default_factory=lambda: ["kill_process", "delete_ram_jail", "remove_cgroup", "remove_netns"]
    )
    purge_verification_results: Dict[str, bool] = field(
        default_factory=lambda: {
            "cgroup_removed": False,
            "netns_removed": False,
            "process_reaped": False,
            "ram_jail_deleted": False,
        }
    )
    incomplete_evidence_fields: List[str] = field(default_factory=list)
    final_disposition: str = "INCONCLUSIVE"
    replay_ciphertext_hash: str = ""
    authentication_metadata: Dict[str, str] = field(default_factory=dict)

    def compute_hash(self) -> str:
        data = asdict(self)
        data.pop("authentication_metadata", None)
        canonical = json.dumps(data, sort_keys=True)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def sign(self, key_bytes: bytes) -> None:
        if key_bytes in PROHIBITED_STATIC_KEYS or len(key_bytes) < 16:
            raise ValueError("Hard-coded or insecure default signing key is prohibited.")

        digest = self.compute_hash()
        hmac_val = hashlib.pbkdf2_hmac("sha256", digest.encode("utf-8"), key_bytes, 10000)
        self.authentication_metadata = {
            "algorithm": "PBKDF2-HMAC-SHA256",
            "signature_hmac": hmac_val.hex(),
            "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        }

    def verify_signature(self, key_bytes: bytes) -> bool:
        if not self.authentication_metadata or "signature_hmac" not in self.authentication_metadata:
            return False
        expected_sig = self.authentication_metadata["signature_hmac"]
        digest = self.compute_hash()
        computed = hashlib.pbkdf2_hmac("sha256", digest.encode("utf-8"), key_bytes, 10000).hex()
        return secrets.compare_digest(expected_sig, computed)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def generate_local_signing_key() -> bytes:
    """Generates a secure random 32-byte key for local runtime signing."""
    return secrets.token_bytes(32)


def create_ash_receipt(
    run_id: str,
    target_identity: str,
    target_hash: str,
    terminal_kind: str = "COLLAPSE",
    final_disposition: str = "INCONCLUSIVE",
    cues: Optional[List[str]] = None,
    key_bytes: Optional[bytes] = None,
    purge_results: Optional[Dict[str, bool]] = None,
) -> AshReceipt:
    if key_bytes is None:
        key_bytes = generate_local_signing_key()

    cue = cues[0] if cues else None
    receipt = AshReceipt(
        run_id=run_id,
        target_identity=target_identity,
        target_hashes={"sha256": target_hash},
        collapse_cue=cue,
        terminal_kind=terminal_kind,
        final_disposition=final_disposition,
        purge_verification_results=purge_results or {
            "cgroup_removed": False,
            "netns_removed": False,
            "process_reaped": False,
            "ram_jail_deleted": False,
        },
    )
    receipt.sign(key_bytes)
    return receipt
