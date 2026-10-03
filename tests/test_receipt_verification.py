"""Receipt signing and verification behavior on hostile or malformed input.

``verify_envelope`` and ``derive_exit_code`` consume files that an attacker
with write access to the receipt directory can edit. They must answer
"invalid" (False / exit code 5) for every malformed receipt and never raise.
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from agent_probe.contract import (  # noqa: E402
    PROHIBITED_STATIC_KEYS,
    ContractError,
    sign_envelope,
    verify_envelope,
)
from agent_probe.receipt import (  # noqa: E402
    EXIT_ALLOW,
    EXIT_CLEANUP_FAILURE,
    EXIT_DENY,
    EXIT_EVIDENCE_FAILURE,
    EXIT_INVALID_RECEIPT,
    build_receipt_envelope,
    derive_exit_code,
)

RECEIPT_TYPE = "cindermote.agent-probe-receipt/v1"
KEY = bytes(range(32))


def _receipt_payload(**overrides: object) -> dict:
    payload = {
        "receipt_version": RECEIPT_TYPE,
        "cleanup_status": "VERIFIED",
        "execution_status": "COMPLETE",
        "gate_decision": "ALLOW",
        "witnesses": {
            "guest_complete": True,
            "egress_complete": True,
            "cleanup_complete": True,
        },
    }
    payload.update(overrides)
    return payload


def _signed(**overrides: object) -> dict:
    return sign_envelope(_receipt_payload(**overrides), RECEIPT_TYPE, KEY)


def test_well_formed_envelope_verifies_and_maps_to_allow() -> None:
    envelope = _signed()
    assert verify_envelope(envelope, KEY, RECEIPT_TYPE) is True
    assert derive_exit_code(envelope, KEY) == EXIT_ALLOW


def _mutations() -> dict:
    def top(name: str, value: object):
        return lambda envelope: envelope.__setitem__(name, value)

    def sig(name: str, value: object):
        return lambda envelope: envelope["signature"].__setitem__(name, value)

    return {
        "payload_sha256 non-ascii": top("payload_sha256", "é" * 64),
        "payload_sha256 int": top("payload_sha256", 7),
        "payload_sha256 null": top("payload_sha256", None),
        "payload_sha256 short": top("payload_sha256", "ab"),
        "payload_sha256 uppercase": lambda e: e.__setitem__("payload_sha256", e["payload_sha256"].upper()),
        "signature_hex non-ascii": sig("signature_hex", "é" * 64),
        "signature_hex int": sig("signature_hex", 7),
        "signature_hex null": sig("signature_hex", None),
        "signature_hex uppercase": lambda e: e["signature"].__setitem__("signature_hex", e["signature"]["signature_hex"].upper()),
        "signature_hex wrong": sig("signature_hex", "0" * 64),
        "key_id non-ascii": sig("key_id", "é" * 32),
        "key_id null": sig("key_id", None),
        "key_id wrong": sig("key_id", "0" * 32),
        "algorithm swapped": sig("algorithm", "none"),
        "signature not an object": top("signature", "AAAA"),
        "signature extra field": lambda e: e["signature"].__setitem__("extra", 1),
        "envelope extra field": top("extra", 1),
        "payload replaced by float": top("payload", {"x": 1.5}),
        "payload replaced by list": top("payload", []),
        "payload mutated": lambda e: e["payload"].__setitem__("gate_decision", "DENY"),
    }


@pytest.mark.parametrize("name", sorted(_mutations()))
def test_malformed_envelope_is_invalid_not_an_exception(name: str) -> None:
    envelope = copy.deepcopy(_signed())
    _mutations()[name](envelope)
    assert verify_envelope(envelope, KEY, RECEIPT_TYPE) is False
    assert derive_exit_code(envelope, KEY) == EXIT_INVALID_RECEIPT


@pytest.mark.parametrize("envelope", [None, 7, "text", [], {}, {"payload": {}}])
def test_non_envelope_values_are_invalid(envelope: object) -> None:
    assert verify_envelope(envelope, KEY, RECEIPT_TYPE) is False
    assert derive_exit_code(envelope, KEY) == EXIT_INVALID_RECEIPT


def test_wrong_payload_type_and_wrong_key_are_invalid() -> None:
    envelope = _signed()
    assert verify_envelope(envelope, KEY, "cindermote.other/v1") is False
    assert verify_envelope(envelope, bytes(reversed(KEY)), RECEIPT_TYPE) is False


@pytest.mark.parametrize("key", [b"", b"short", b"x" * 31, bytearray(KEY), "text", None])
def test_short_or_mistyped_keys_cannot_sign_or_verify(key: object) -> None:
    with pytest.raises(ContractError):
        sign_envelope(_receipt_payload(), RECEIPT_TYPE, key)  # type: ignore[arg-type]
    assert verify_envelope(_signed(), key, RECEIPT_TYPE) is False  # type: ignore[arg-type]


@pytest.mark.parametrize("key", sorted(PROHIBITED_STATIC_KEYS))
def test_publicly_known_static_keys_are_refused(key: bytes) -> None:
    with pytest.raises(ContractError):
        sign_envelope(_receipt_payload(), RECEIPT_TYPE, key)
    assert verify_envelope(_signed(), key, RECEIPT_TYPE) is False


def test_known_default_32_byte_keys_are_in_the_prohibited_set() -> None:
    # The two historical 32-byte placeholders must be refused on the real
    # signing path, not only in a module that no entry point calls.
    for key in (b"cindermote-observer-key-32bytes!", b"12345678901234567890123456789012"):
        assert len(key) == 32
        assert key in PROHIBITED_STATIC_KEYS
        with pytest.raises(ContractError):
            sign_envelope(_receipt_payload(), RECEIPT_TYPE, key)


@pytest.mark.parametrize(
    "witnesses",
    [
        None,
        {},
        [],
        "yes",
        {"guest_complete": True, "egress_complete": True},
        {"guest_complete": True, "egress_complete": True, "cleanup_complete": 1},
        {"guest_complete": True, "egress_complete": True, "cleanup_complete": False},
        {"guest_complete": True, "egress_complete": True, "cleanup_complete": True, "extra": True},
    ],
)
def test_allow_requires_the_complete_witness_table(witnesses: object) -> None:
    payload = _receipt_payload()
    if witnesses is None:
        del payload["witnesses"]
    else:
        payload["witnesses"] = witnesses
    envelope = sign_envelope(payload, RECEIPT_TYPE, KEY)
    assert derive_exit_code(envelope, KEY) == EXIT_EVIDENCE_FAILURE


def test_exit_codes_follow_cleanup_before_decision() -> None:
    assert derive_exit_code(_signed(cleanup_status="UNVERIFIED"), KEY) == EXIT_CLEANUP_FAILURE
    assert derive_exit_code(_signed(gate_decision="DENY"), KEY) == EXIT_DENY
    assert derive_exit_code(_signed(gate_decision="EVALUATION_INCOMPLETE"), KEY) == EXIT_EVIDENCE_FAILURE
    assert derive_exit_code(_signed(gate_decision="SOMETHING_ELSE"), KEY) == EXIT_INVALID_RECEIPT


def _receipt_inputs() -> dict:
    return {
        "job_manifest": {"job_id": "job-0123456789abcdef", "target": {"target_hash": "1" * 64}},
        "road_frozen": {"road": "frozen"},
        "road_walked": {"road": "walked"},
        "road_diff": {"road": "diff"},
        "guest_evidence_manifest": {"guest_evidence_root": "2" * 64, "complete": True},
        "host_lifecycle": {
            "host_lifecycle_root": "3" * 64,
            "egress_witness_complete": True,
            "cleanup_verified": True,
        },
        "observer_key": KEY,
    }


def test_builder_refuses_to_fabricate_an_allow() -> None:
    inputs = _receipt_inputs()
    good = build_receipt_envelope(
        **inputs, execution_status="COMPLETE", gate_decision="ALLOW", cleanup_status="VERIFIED"
    )
    assert derive_exit_code(good, KEY) == EXIT_ALLOW

    with pytest.raises(ValueError):
        build_receipt_envelope(
            **inputs, execution_status="COMPLETE", gate_decision="ALLOW", cleanup_status="UNVERIFIED"
        )
    with pytest.raises(ValueError):
        build_receipt_envelope(
            **inputs, execution_status="INFRASTRUCTURE_FAILED", gate_decision="ALLOW", cleanup_status="VERIFIED"
        )
    incomplete = _receipt_inputs()
    incomplete["guest_evidence_manifest"] = {"guest_evidence_root": "2" * 64, "complete": False}
    with pytest.raises(ValueError):
        build_receipt_envelope(
            **incomplete, execution_status="COMPLETE", gate_decision="ALLOW", cleanup_status="VERIFIED"
        )


# --- legacy (observer) receipts -------------------------------------------------

from observer.receipt import sign_receipt, verify_signature  # noqa: E402


def _legacy_receipt() -> dict:
    body = {"identity": {"job_id": "mf-run-0123abcd"}, "gate": {"final_decision": "DENY"}}
    return {**body, "receipt_signature": sign_receipt(body, KEY)}


def test_legacy_receipt_signature_round_trip_and_mutation() -> None:
    receipt = _legacy_receipt()
    assert verify_signature(receipt, KEY) is True
    receipt["gate"]["final_decision"] = "ALLOW"
    assert verify_signature(receipt, KEY) is False


@pytest.mark.parametrize("signature", ["é" * 64, 7, None, [], {}, "", "0" * 64])
def test_legacy_receipt_with_hostile_signature_is_invalid_not_an_exception(signature: object) -> None:
    receipt = _legacy_receipt()
    receipt["receipt_signature"] = signature
    assert verify_signature(receipt, KEY) is False


def test_legacy_receipt_with_nan_payload_is_invalid_not_an_exception() -> None:
    receipt = _legacy_receipt()
    receipt["gate"]["score"] = float("nan")
    assert verify_signature(receipt, KEY) is False
