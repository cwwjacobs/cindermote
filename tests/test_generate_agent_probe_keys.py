from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "generate-agent-probe-keys.py"


def test_reuse_preserves_existing_observer_and_creates_matching_quarantine_keys(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    observer = project / ".observer_key"
    original = os.urandom(32)
    observer.write_bytes(original)
    observer.chmod(0o600)
    private = tmp_path / "offline" / "quarantine.key"
    base = [
        sys.executable,
        str(SCRIPT),
        "--project-root",
        str(project),
        "--offline-private-key",
        str(private),
    ]

    rejected = subprocess.run(base, capture_output=True, text=True, check=False)
    assert rejected.returncode != 0
    assert "--reuse-observer-key" in rejected.stderr
    assert observer.read_bytes() == original
    assert not private.exists()

    created = subprocess.run(
        [*base, "--reuse-observer-key"], capture_output=True, text=True, check=False
    )
    assert created.returncode == 0, created.stderr
    public = project / "policy" / "agent-probe-quarantine.x25519.pub"
    assert observer.read_bytes() == original
    assert observer.stat().st_mode & 0o777 == 0o600
    assert private.stat().st_mode & 0o777 == 0o600
    assert public.stat().st_mode & 0o777 == 0o444
    assert len(public.read_bytes()) == 32
    assert x25519.X25519PrivateKey.from_private_bytes(private.read_bytes()).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    ) == public.read_bytes()


def test_key_generator_rejects_private_key_symlink_before_writing(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    private = tmp_path / "offline" / "quarantine.key"
    private.parent.mkdir()
    destination = tmp_path / "unexpected.key"
    private.symlink_to(destination)

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--project-root",
            str(project),
            "--offline-private-key",
            str(private),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "offline private key already exists" in result.stderr
    assert private.is_symlink()
    assert not destination.exists()
    assert not (project / ".observer_key").exists()
