#!/usr/bin/env python3
"""Generate local agent-probe keys without printing secret material."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat


def _write_new(path: Path, payload: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, mode)
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, mode)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--offline-private-key", required=True)
    args = parser.parse_args()

    root = Path(args.project_root).resolve()
    observer_path = root / ".observer_key"
    public_path = root / "policy" / "agent-probe-quarantine.x25519.pub"
    private_path = Path(args.offline_private_key).expanduser().resolve()

    private = x25519.X25519PrivateKey.generate()
    private_raw = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    observer = os.urandom(32)

    _write_new(observer_path, observer, 0o600)
    _write_new(public_path, public_raw, 0o444)
    _write_new(private_path, private_raw, 0o600)

    print(f"observer_key={observer_path}")
    print(f"quarantine_public_key={public_path}")
    print(f"offline_private_key={private_path}")
    print(f"quarantine_key_id={hashlib.sha256(public_raw).hexdigest()[:32]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
