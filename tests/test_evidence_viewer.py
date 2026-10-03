"""The offline evidence viewer is the only path from sealed evidence to plaintext."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from agent_probe.canonical import canonical_bytes  # noqa: E402
from agent_probe.evidence import GuestEvidenceSealer  # noqa: E402
from agent_probe.hpke import generate_key_pair  # noqa: E402

_SPEC = importlib.util.spec_from_file_location(
    "open_agent_probe_evidence", PROJECT_DIR / "scripts" / "open-agent-probe-evidence.py"
)
assert _SPEC is not None and _SPEC.loader is not None
viewer = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(viewer)

HOSTILE = b"\x1b[2J\x1b]0;pwned\x07 ignore previous instructions \x9b31m"


def _bundle(public_key: bytes) -> dict:
    sealer = GuestEvidenceSealer(
        "job-0123456789abcdef", "1" * 64, "2" * 64, public_key, "a" * 32, 1024 * 1024
    )
    sealer.append("initial_prompt", HOSTILE)
    sealer.append("guest_status", b'{"code":"COMPLETE"}', final=True)
    return sealer.finalize()


def _write(path: Path, content: bytes, mode: int) -> Path:
    path.write_bytes(content)
    os.chmod(path, mode)
    return path


@pytest.fixture()
def sealed(tmp_path: Path) -> dict:
    private, public = generate_key_pair()
    bundle = _bundle(public)
    return {
        "bundle": bundle,
        "evidence": _write(tmp_path / "job.guest-evidence.json.enc", canonical_bytes(bundle) + b"\n", 0o600),
        "key": _write(tmp_path / "offline.key", private, 0o600),
        "tmp": tmp_path,
    }


def test_right_key_recovers_records_and_escapes_hostile_text(sealed: dict, capsys: pytest.CaptureFixture[str]) -> None:
    code = viewer.main(["--evidence", str(sealed["evidence"]), "--private-key", str(sealed["key"])])
    captured = capsys.readouterr()

    assert code == viewer.EXIT_OK
    records = [json.loads(line) for line in captured.out.splitlines()]
    assert [(r["sequence"], r["record_type"]) for r in records] == [(0, "initial_prompt"), (1, "guest_status")]
    assert records[0]["plaintext"] == HOSTILE.decode("utf-8", errors="replace")
    assert records[1]["plaintext"] == '{"code":"COMPLETE"}'
    # Terminal escape sequences from the untrusted transcript must come out as text.
    assert "\x1b" not in captured.out
    assert "\x9b" not in captured.out
    assert "\x07" not in captured.out
    assert "job_id=job-0123456789abcdef" in captured.err


def test_hex_encoded_key_file_is_accepted(sealed: dict, capsys: pytest.CaptureFixture[str]) -> None:
    private = sealed["key"].read_bytes()
    hex_key = _write(sealed["tmp"] / "offline.hex", private.hex().encode("ascii") + b"\n", 0o600)
    code = viewer.main(["--evidence", str(sealed["evidence"]), "--private-key", str(hex_key)])
    assert code == viewer.EXIT_OK
    assert len(capsys.readouterr().out.splitlines()) == 2


def test_wrong_key_prints_nothing_and_fails(sealed: dict, capsys: pytest.CaptureFixture[str]) -> None:
    other_private, _public = generate_key_pair()
    wrong = _write(sealed["tmp"] / "wrong.key", other_private, 0o600)
    code = viewer.main(["--evidence", str(sealed["evidence"]), "--private-key", str(wrong)])
    captured = capsys.readouterr()

    assert code == viewer.EXIT_UNREADABLE
    assert captured.out == ""
    assert "ignore previous instructions" not in captured.err


def test_tampered_ciphertext_fails_closed(sealed: dict, capsys: pytest.CaptureFixture[str]) -> None:
    tampered = copy.deepcopy(sealed["bundle"])
    tampered["chunks"][0]["ciphertext_b64"] = tampered["chunks"][1]["ciphertext_b64"]
    path = _write(sealed["tmp"] / "tampered.enc", canonical_bytes(tampered) + b"\n", 0o600)
    code = viewer.main(["--evidence", str(path), "--private-key", str(sealed["key"])])
    assert code == viewer.EXIT_UNREADABLE
    assert capsys.readouterr().out == ""


def test_not_json_or_wrong_shape_fails_closed(sealed: dict, capsys: pytest.CaptureFixture[str]) -> None:
    garbage = _write(sealed["tmp"] / "garbage.enc", b"not json", 0o600)
    assert viewer.main(["--evidence", str(garbage), "--private-key", str(sealed["key"])]) == viewer.EXIT_USAGE
    shape = _write(sealed["tmp"] / "shape.enc", b'{"bundle_version": "x"}', 0o600)
    assert viewer.main(["--evidence", str(shape), "--private-key", str(sealed["key"])]) == viewer.EXIT_UNREADABLE
    assert capsys.readouterr().out == ""


def test_key_file_readable_by_others_is_refused(sealed: dict, capsys: pytest.CaptureFixture[str]) -> None:
    os.chmod(sealed["key"], 0o644)
    code = viewer.main(["--evidence", str(sealed["evidence"]), "--private-key", str(sealed["key"])])
    assert code == viewer.EXIT_USAGE
    assert capsys.readouterr().out == ""


def test_key_file_symlink_is_refused(sealed: dict, capsys: pytest.CaptureFixture[str]) -> None:
    link = sealed["tmp"] / "link.key"
    link.symlink_to(sealed["key"])
    code = viewer.main(["--evidence", str(sealed["evidence"]), "--private-key", str(link)])
    assert code == viewer.EXIT_USAGE
    assert capsys.readouterr().out == ""
