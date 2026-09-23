from __future__ import annotations

import copy

import pytest

from cindermote.agent_probe.canonical import CanonicalizationError, canonical_bytes, sha256_hex
from cindermote.agent_probe.evidence import GuestEvidenceSealer, decrypt_bundle, validate_bundle
from cindermote.agent_probe.hpke import generate_key_pair, open_base, seal_base
from cindermote.agent_probe.secretstream import EncryptedChunk, PushStream, pull_all, random_key


def test_canonical_json_rejects_float_and_is_stable() -> None:
    assert canonical_bytes({"b": 2, "a": [True, "x"]}) == b'{"a":[true,"x"],"b":2}'
    assert sha256_hex({"b": 2, "a": 1}) == sha256_hex({"a": 1, "b": 2})
    with pytest.raises(CanonicalizationError):
        canonical_bytes({"unsafe": 1.5})


def test_rfc9180_base_mode_round_trip_and_wrong_key_rejection() -> None:
    private, public = generate_key_pair()
    wrong_private, _ = generate_key_pair()
    box = seal_base(public, b"content-encryption-key", info=b"info", aad=b"aad")
    assert open_base(private, box.enc, box.ciphertext, info=b"info", aad=b"aad") == b"content-encryption-key"
    with pytest.raises(Exception):
        open_base(wrong_private, box.enc, box.ciphertext, info=b"info", aad=b"aad")


def test_actual_libsodium_secretstream_final_tag_and_tamper_rejection() -> None:
    key = random_key()
    stream = PushStream(key)
    chunks = [
        stream.push(b"one", aad=b"a"),
        stream.push(b"two", aad=b"b", final=True),
    ]
    assert pull_all(bytes(key), stream.header, chunks) == [b"one", b"two"]
    bad = list(chunks)
    corrupted = bytearray(bad[0].ciphertext)
    corrupted[-1] ^= 1
    bad[0] = EncryptedChunk(0, bad[0].aad, bytes(corrupted), False)
    with pytest.raises(Exception):
        pull_all(bytes(key), stream.header, bad)


def test_guest_evidence_bundle_uses_hpke_and_secretstream() -> None:
    private, public = generate_key_pair()
    sealer = GuestEvidenceSealer(
        "job-0123456789abcdef",
        "1" * 64,
        "2" * 64,
        public,
        "a" * 32,
        1024 * 1024,
    )
    sealer.append("initial_prompt", b"hostile prompt text")
    sealer.append("guest_status", b'{"code":"COMPLETE"}', final=True)
    bundle = sealer.finalize()
    validate_bundle(bundle)
    assert decrypt_bundle(bundle, private) == [b"hostile prompt text", b'{"code":"COMPLETE"}']
    assert b"hostile prompt text" not in canonical_bytes(bundle)

    tampered = copy.deepcopy(bundle)
    tampered["chunks"][0]["ciphertext_b64"] = tampered["chunks"][1]["ciphertext_b64"]
    with pytest.raises(Exception):
        validate_bundle(tampered)
