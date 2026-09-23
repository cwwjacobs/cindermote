"""Guest-side encrypted evidence bundle and forensic verification helpers."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any

from .canonical import canonical_bytes, sha256_hex
from .hpke import open_base, seal_base
from .secretstream import ABYTES, HEADER_BYTES, EncryptedChunk, PushStream, memzero, pull_all, random_key

SUITE_ID = "HPKE-0020-0001-0003+SECRETSTREAM-XCHACHA20POLY1305"
ZERO_HASH = "0" * 64
RECORD_TYPES = frozenset({"initial_prompt", "model_response", "tool_proposal", "broker_denial", "tool_result", "guest_status", "guest_halt"})


class EvidenceError(ValueError):
    pass


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: Any, name: str, maximum: int = 8 * 1024 * 1024) -> bytes:
    if not isinstance(value, str) or len(value) > maximum * 2:
        raise EvidenceError(f"{name} is invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise EvidenceError(f"{name} is not canonical base64") from exc
    if len(decoded) > maximum:
        raise EvidenceError(f"{name} exceeds its byte limit")
    return decoded


@dataclass
class GuestEvidenceSealer:
    job_id: str
    target_hash: str
    road_frozen_hash: str
    quarantine_public_key: bytes
    quarantine_key_id: str
    max_evidence_bytes: int

    def __post_init__(self) -> None:
        self._cek = random_key()
        info = canonical_bytes({
            "profile": "agent-probe/v0",
            "job_id": self.job_id,
            "target_hash": self.target_hash,
            "road_frozen_hash": self.road_frozen_hash,
            "purpose": "guest-evidence-key-wrap",
        })
        aad = canonical_bytes({"key_id": self.quarantine_key_id, "suite_id": SUITE_ID})
        box = seal_base(self.quarantine_public_key, bytes(self._cek), info=info, aad=aad)
        self._hpke_info = info
        self._hpke_aad = aad
        self._enc = box.enc
        self._wrapped_cek = box.ciphertext
        self._stream = PushStream(self._cek)
        self._chunks: list[EncryptedChunk] = []
        self._previous_ciphertext_hash = ZERO_HASH
        self._plaintext_bytes = 0
        self._ciphertext_bytes = 0
        self._finalized = False

    def append(self, record_type: str, payload: bytes, *, final: bool = False) -> None:
        if self._finalized:
            raise EvidenceError("evidence stream is finalized")
        if not isinstance(record_type, str) or not 1 <= len(record_type) <= 64:
            raise EvidenceError("record type is invalid")
        sequence = len(self._chunks)
        aad = canonical_bytes({
            "profile": "agent-probe/v0",
            "job_id": self.job_id,
            "target_hash": self.target_hash,
            "road_frozen_hash": self.road_frozen_hash,
            "stream_id": "guest-transcript",
            "sequence": sequence,
            "previous_ciphertext_hash": self._previous_ciphertext_hash,
            "record_type": record_type,
            "final": final,
        })
        chunk = self._stream.push(payload, aad=aad, final=final)
        projected = self._ciphertext_bytes + len(chunk.ciphertext)
        if projected > self.max_evidence_bytes:
            raise EvidenceError("encrypted evidence budget exceeded")
        self._chunks.append(chunk)
        self._plaintext_bytes += len(payload)
        self._ciphertext_bytes = projected
        self._previous_ciphertext_hash = hashlib.sha256(chunk.ciphertext).hexdigest()
        if final:
            self._finalized = True
            memzero(self._cek)

    def finalize(self) -> dict[str, Any]:
        if not self._finalized:
            self.append("guest_halt", b"", final=True)
        chunk_records = [
            {
                "sequence": chunk.sequence,
                "aad_b64": _b64(chunk.aad),
                "ciphertext_b64": _b64(chunk.ciphertext),
                "ciphertext_sha256": hashlib.sha256(chunk.ciphertext).hexdigest(),
                "final": chunk.final,
            }
            for chunk in self._chunks
        ]
        root_payload = {
            "stream_header_sha256": hashlib.sha256(self._stream.header).hexdigest(),
            "chunks": [record["ciphertext_sha256"] for record in chunk_records],
        }
        manifest = {
            "manifest_version": "cindermote.guest-evidence/v1",
            "job_id": self.job_id,
            "target_hash": self.target_hash,
            "road_frozen_hash": self.road_frozen_hash,
            "suite_id": SUITE_ID,
            "quarantine_key_id": self.quarantine_key_id,
            "guest_evidence_root": sha256_hex(root_payload),
            "complete": bool(chunk_records and chunk_records[-1]["final"]),
            "sequence_gaps": 0,
            "total_plaintext_bytes": self._plaintext_bytes,
            "total_ciphertext_bytes": self._ciphertext_bytes,
            "chunk_count": len(chunk_records),
        }
        return {
            "bundle_version": "cindermote.guest-evidence-bundle/v1",
            "manifest": manifest,
            "hpke": {
                "enc_b64": _b64(self._enc),
                "wrapped_cek_b64": _b64(self._wrapped_cek),
                "info_b64": _b64(self._hpke_info),
                "aad_b64": _b64(self._hpke_aad),
            },
            "secretstream_header_b64": _b64(self._stream.header),
            "chunks": chunk_records,
        }


def validate_bundle(bundle: Any, *, max_evidence_bytes: int = 4 * 1024 * 1024) -> dict[str, Any]:
    if not isinstance(bundle, dict) or set(bundle) != {"bundle_version", "manifest", "hpke", "secretstream_header_b64", "chunks"}:
        raise EvidenceError("evidence bundle shape changed")
    if bundle["bundle_version"] != "cindermote.guest-evidence-bundle/v1":
        raise EvidenceError("unsupported evidence bundle")
    manifest = bundle["manifest"]
    manifest_keys = {
        "manifest_version", "job_id", "target_hash", "road_frozen_hash", "suite_id",
        "quarantine_key_id", "guest_evidence_root", "complete", "sequence_gaps",
        "total_plaintext_bytes", "total_ciphertext_bytes", "chunk_count",
    }
    if not isinstance(manifest, dict) or set(manifest) != manifest_keys:
        raise EvidenceError("evidence manifest shape changed")
    if manifest["manifest_version"] != "cindermote.guest-evidence/v1" or manifest["suite_id"] != SUITE_ID:
        raise EvidenceError("evidence manifest suite mismatch")
    for name in ("target_hash", "road_frozen_hash", "guest_evidence_root"):
        value = manifest[name]
        if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
            raise EvidenceError(f"manifest {name} is invalid")
    if not isinstance(manifest["job_id"], str) or not manifest["job_id"].startswith("job-"):
        raise EvidenceError("manifest job id is invalid")
    if not isinstance(manifest["quarantine_key_id"], str) or not 16 <= len(manifest["quarantine_key_id"]) <= 64:
        raise EvidenceError("manifest key id is invalid")
    if manifest["complete"] is not True or manifest["sequence_gaps"] != 0:
        raise EvidenceError("evidence manifest is incomplete")
    for name in ("total_plaintext_bytes", "total_ciphertext_bytes", "chunk_count"):
        value = manifest[name]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise EvidenceError(f"manifest {name} is invalid")
    if manifest["total_plaintext_bytes"] > max_evidence_bytes:
        raise EvidenceError("plaintext evidence accounting exceeds budget")

    hpke = bundle["hpke"]
    if not isinstance(hpke, dict) or set(hpke) != {"enc_b64", "wrapped_cek_b64", "info_b64", "aad_b64"}:
        raise EvidenceError("HPKE envelope shape changed")
    enc = _unb64(hpke["enc_b64"], "enc", 64)
    wrapped = _unb64(hpke["wrapped_cek_b64"], "wrapped CEK", 256)
    info = _unb64(hpke["info_b64"], "HPKE info", 16 * 1024)
    hpke_aad = _unb64(hpke["aad_b64"], "HPKE aad", 16 * 1024)
    if len(enc) != 32 or len(wrapped) != 48:
        raise EvidenceError("HPKE key-wrap lengths are invalid")
    try:
        info_value = __import__("json").loads(info)
        aad_value = __import__("json").loads(hpke_aad)
    except (UnicodeDecodeError, ValueError) as exc:
        raise EvidenceError("HPKE metadata is malformed") from exc
    expected_info = {
        "profile": "agent-probe/v0",
        "job_id": manifest["job_id"],
        "target_hash": manifest["target_hash"],
        "road_frozen_hash": manifest["road_frozen_hash"],
        "purpose": "guest-evidence-key-wrap",
    }
    expected_aad = {"key_id": manifest["quarantine_key_id"], "suite_id": SUITE_ID}
    if info_value != expected_info or canonical_bytes(info_value) != info:
        raise EvidenceError("HPKE info binding is invalid")
    if aad_value != expected_aad or canonical_bytes(aad_value) != hpke_aad:
        raise EvidenceError("HPKE AAD binding is invalid")

    chunks = bundle["chunks"]
    if not isinstance(chunks, list) or not chunks or len(chunks) > 1024:
        raise EvidenceError("evidence chunk list is invalid")
    total = 0
    hashes: list[str] = []
    previous_hash = ZERO_HASH
    for index, record in enumerate(chunks):
        if not isinstance(record, dict) or set(record) != {"sequence", "aad_b64", "ciphertext_b64", "ciphertext_sha256", "final"}:
            raise EvidenceError("evidence chunk shape changed")
        if record["sequence"] != index or record["final"] is not (index == len(chunks) - 1):
            raise EvidenceError("evidence sequence or final tag is invalid")
        ciphertext = _unb64(record["ciphertext_b64"], "ciphertext")
        aad = _unb64(record["aad_b64"], "aad", 64 * 1024)
        if len(ciphertext) < ABYTES:
            raise EvidenceError("ciphertext chunk is too short")
        try:
            aad_value = __import__("json").loads(aad)
        except (UnicodeDecodeError, ValueError) as exc:
            raise EvidenceError("chunk AAD is malformed") from exc
        if not isinstance(aad_value, dict) or set(aad_value) != {
            "profile", "job_id", "target_hash", "road_frozen_hash", "stream_id",
            "sequence", "previous_ciphertext_hash", "record_type", "final",
        }:
            raise EvidenceError("chunk AAD shape changed")
        expected_binding = {
            "profile": "agent-probe/v0",
            "job_id": manifest["job_id"],
            "target_hash": manifest["target_hash"],
            "road_frozen_hash": manifest["road_frozen_hash"],
            "stream_id": "guest-transcript",
            "sequence": index,
            "previous_ciphertext_hash": previous_hash,
            "final": record["final"],
        }
        for name, value in expected_binding.items():
            if aad_value.get(name) != value:
                raise EvidenceError(f"chunk AAD binding differs: {name}")
        if aad_value.get("record_type") not in RECORD_TYPES or canonical_bytes(aad_value) != aad:
            raise EvidenceError("chunk AAD record type or canonical form is invalid")
        digest = hashlib.sha256(ciphertext).hexdigest()
        if digest != record["ciphertext_sha256"]:
            raise EvidenceError("ciphertext digest mismatch")
        hashes.append(digest)
        previous_hash = digest
        total += len(ciphertext)
        if total > max_evidence_bytes:
            raise EvidenceError("evidence bundle exceeds budget")
    header = _unb64(bundle["secretstream_header_b64"], "secretstream header", 128)
    if len(header) != HEADER_BYTES:
        raise EvidenceError("SecretStream header length is invalid")
    expected_root = sha256_hex({"stream_header_sha256": hashlib.sha256(header).hexdigest(), "chunks": hashes})
    if manifest["guest_evidence_root"] != expected_root:
        raise EvidenceError("guest evidence root mismatch")
    if manifest["chunk_count"] != len(chunks) or manifest["total_ciphertext_bytes"] != total:
        raise EvidenceError("evidence manifest accounting mismatch")
    return bundle


def decrypt_bundle(bundle: dict[str, Any], recipient_private_key: bytes) -> list[bytes]:
    validate_bundle(bundle)
    hpke = bundle["hpke"]
    if not isinstance(hpke, dict) or set(hpke) != {"enc_b64", "wrapped_cek_b64", "info_b64", "aad_b64"}:
        raise EvidenceError("HPKE envelope shape changed")
    cek = bytearray(open_base(
        recipient_private_key,
        _unb64(hpke["enc_b64"], "enc", 64),
        _unb64(hpke["wrapped_cek_b64"], "wrapped CEK", 256),
        info=_unb64(hpke["info_b64"], "HPKE info", 16 * 1024),
        aad=_unb64(hpke["aad_b64"], "HPKE aad", 16 * 1024),
    ))
    try:
        chunks = [
            EncryptedChunk(
                record["sequence"],
                _unb64(record["aad_b64"], "aad", 64 * 1024),
                _unb64(record["ciphertext_b64"], "ciphertext"),
                record["final"],
            )
            for record in bundle["chunks"]
        ]
        return pull_all(bytes(cek), _unb64(bundle["secretstream_header_b64"], "header", 128), chunks)
    finally:
        memzero(cek)
