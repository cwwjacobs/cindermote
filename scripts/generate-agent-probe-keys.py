#!/usr/bin/env python3
"""Generate local agent-probe keys without printing secret material."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat


def _write_new(path: Path, payload: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, mode
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short key write")
            view = view[written:]
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--offline-private-key", required=True)
    parser.add_argument(
        "--reuse-observer-key",
        action="store_true",
        help="retain an existing private observer key while creating a new quarantine key pair",
    )
    args = parser.parse_args()

    root = Path(args.project_root).resolve()
    observer_path = root / ".observer_key"
    public_path = root / "policy" / "agent-probe-quarantine.x25519.pub"
    private_input = Path(args.offline_private_key).expanduser()
    private_path = private_input.parent.resolve() / private_input.name

    if public_path.exists() or public_path.is_symlink():
        parser.error(f"quarantine public key already exists: {public_path}")
    if private_path.exists() or private_path.is_symlink():
        parser.error(f"offline private key already exists: {private_path}")
    observer_exists = observer_path.exists() or observer_path.is_symlink()
    if args.reuse_observer_key:
        if not observer_exists:
            parser.error("--reuse-observer-key requires an existing observer key")
        metadata = observer_path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != os.getuid()
            or metadata.st_size != 32
        ):
            parser.error("existing observer key must be an owned, 0600, 32-byte regular file")
    elif observer_exists:
        parser.error("observer key already exists; use --reuse-observer-key to retain it")

    private = x25519.X25519PrivateKey.generate()
    private_raw = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    if not args.reuse_observer_key:
        _write_new(observer_path, os.urandom(32), 0o600)
    _write_new(public_path, public_raw, 0o444)
    _write_new(private_path, private_raw, 0o600)

    print(f"observer_key={observer_path}")
    print(f"quarantine_public_key={public_path}")
    print(f"offline_private_key={private_path}")
    print(f"quarantine_key_id={hashlib.sha256(public_raw).hexdigest()[:32]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
