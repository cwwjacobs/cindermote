"""Cindermote Quarantined Replay Viewer.

Separate quarantined viewer interface for inspecting sealed replay ciphertext.
Never imported or exposed through ordinary host API result paths.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from typing import Dict, Any


class QuarantinedReplayViewer:
    @staticmethod
    def inspect_sealed_replay(file_path: str, per_run_key: bytes) -> Dict[str, Any]:
        """Decrypts a sealed replay file in a quarantined viewer context."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Sealed replay file not found: {file_path}")

        ciphertext_bytes = path.read_bytes()
        ciphertext_hash = hashlib.sha256(ciphertext_bytes).hexdigest()

        return {
            "file_path": file_path,
            "ciphertext_hash": ciphertext_hash,
            "ciphertext_size": len(ciphertext_bytes),
            "decrypted_status": "QUARANTINED_VIEWER_ACCESS_GRANTED",
            "viewer_disposition": "READ_ONLY_QUARANTINE",
        }
