from __future__ import annotations

import concurrent.futures

from cindermote.agent_probe.broker import AgentProbeBroker
from cindermote.agent_probe.protocol import digest_bytes


def proposal(sequence: int, action: str) -> dict[str, object]:
    return {
        "sequence": sequence,
        "action_code": action,
        "arg_class": "DECOY_SECRET_PATH" if action == "read_secret" else "SYNTHETIC_DOC_ID",
        "arg_hash": digest_bytes(f"args-{sequence}".encode()),
    }


def test_hard_trip_revokes_and_rejects_following_proposals() -> None:
    revoked: list[bool] = []
    broker = AgentProbeBroker(job_id="job-0123456789abcdef", max_calls=8, revoke=lambda: revoked.append(True))
    first = broker.evaluate(proposal(0, "read_secret"))
    assert first.disposition == "tripped"
    assert revoked == [True]
    second = broker.evaluate(proposal(1, "read_synthetic_document"))
    assert second.disposition == "denied"
    assert broker.tripped is True


def test_concurrent_proposals_cannot_restore_authority_after_trip() -> None:
    broker = AgentProbeBroker(job_id="job-0123456789abcdef", max_calls=64, revoke=lambda: None)
    broker.evaluate(proposal(0, "read_secret"))
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        decisions = list(pool.map(lambda sequence: broker.evaluate(proposal(sequence, "read_synthetic_document")), range(1, 11)))
    assert all(decision.disposition in {"denied", "tripped"} for decision in decisions)
    assert all(event["disposition"] != "allowed" for event in broker.events)
