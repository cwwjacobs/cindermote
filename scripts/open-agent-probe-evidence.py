#!/usr/bin/env python3
"""Open a sealed agent-probe evidence bundle with the offline private key.

This is the quarantined viewer for ``quarantine/agent-probe/<job>.guest-evidence.json.enc``.
The bundle holds the raw guest transcript (the untrusted target text, model
prompts and responses, tool proposals and results) encrypted to the offline
X25519 key created by ``scripts/generate-agent-probe-keys.py``.

Run it on an isolated analyst machine. Its output is attacker-influenced text:
do not paste it into a trusted agent or an unsandboxed terminal-aware tool.
Records are written as JSON Lines with the plaintext as an escaped JSON string,
so control characters and terminal escape sequences inside hostile content are
printed as text and are never interpreted.

Exit status: 0 success, 2 usage or unsafe key file, 3 bundle invalid or not
decryptable with this key (nothing is printed to stdout in that case).
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import stat
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

MAX_BUNDLE_BYTES = 16 * 1024 * 1024

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_UNREADABLE = 3


def _read_private_key(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
            raise ValueError("private key file must be a regular file readable only by its owner (chmod 600)")
        raw = os.read(descriptor, 256)
    finally:
        os.close(descriptor)
    if len(raw) == 32:
        return raw
    candidate = raw.strip()
    if len(candidate) == 32:
        return candidate
    try:
        decoded = bytes.fromhex(candidate.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        decoded = b""
    if len(decoded) == 32:
        return decoded
    raise ValueError("private key file must hold a raw 32-byte X25519 key or 64 hex characters")


def _read_bundle(path: Path) -> object:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("evidence bundle must be a regular file")
        raw = os.read(descriptor, MAX_BUNDLE_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > MAX_BUNDLE_BYTES:
        raise ValueError("evidence bundle exceeds the size limit")
    return json.loads(raw)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--evidence", required=True, help="path to <job>.guest-evidence.json.enc")
    parser.add_argument("--private-key", required=True, help="offline X25519 private key (mode 0600)")
    args = parser.parse_args(argv)

    try:
        private_key = _read_private_key(Path(args.private_key).expanduser())
        bundle = _read_bundle(Path(args.evidence).expanduser())
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    from agent_probe.evidence import EvidenceError, decrypt_bundle
    from agent_probe.hpke import HpkeError
    from agent_probe.secretstream import SecretStreamError

    try:
        plaintexts = decrypt_bundle(bundle, private_key)  # type: ignore[arg-type]
        aads = [json.loads(base64.b64decode(chunk["aad_b64"], validate=True)) for chunk in bundle["chunks"]]  # type: ignore[index]
    except (EvidenceError, HpkeError, SecretStreamError, KeyError, TypeError, ValueError) as exc:
        # Bounded message only: never echo bundle content.
        print(f"error: evidence bundle is invalid or not sealed to this key ({type(exc).__name__})", file=sys.stderr)
        return EXIT_UNREADABLE

    manifest = bundle["manifest"]  # type: ignore[index]
    print(
        "job_id={job_id} guest_evidence_root={root} records={count}".format(
            job_id=manifest["job_id"], root=manifest["guest_evidence_root"], count=len(plaintexts)
        ),
        file=sys.stderr,
    )
    for aad, plaintext in zip(aads, plaintexts):
        record = {
            "sequence": aad.get("sequence"),
            "record_type": aad.get("record_type"),
            "plaintext": plaintext.decode("utf-8", errors="replace"),
        }
        sys.stdout.write(json.dumps(record, ensure_ascii=True, sort_keys=True) + "\n")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
