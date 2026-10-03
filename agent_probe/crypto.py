"""Unified facade over Cindermote's two evidence-encryption modules.

    - **RFC 9180 HPKE Base Mode** (``agent_probe.hpke``): DHKEM(X25519,
      HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305, built on PyCA
      ``cryptography`` primitives.
    - **Secretstream** (``agent_probe.secretstream``): libsodium's
      XChaCha20-Poly1305 stream construction through ``ctypes``.

Neither module has had an independent security audit. Their correctness is
checked by a published known-answer vector and by interoperability with PyCA's
own HPKE implementation in ``tests/test_crypto_vectors.py``.
"""

from __future__ import annotations

from typing import List, Tuple

from .hpke import (
    HpkeError,
    SealedBox,
    generate_key_pair as hpke_generate_key_pair,
    open_base as hpke_open_base,
    seal_base as hpke_seal_base,
)

from .secretstream import (
    EncryptedChunk,
    PushStream,
    SecretStreamError,
    memzero,
    pull_all,
    random_key,
)


class CryptoEngine:
    """Unified Cryptographic Engine providing HPKE and SecretStream operations."""

    @staticmethod
    def generate_hpke_keypair() -> Tuple[bytes, bytes]:
        """Generate a raw 32-byte X25519 (private_key, public_key) pair."""
        return hpke_generate_key_pair()

    @staticmethod
    def hpke_seal(
        recipient_public_key: bytes,
        plaintext: bytes,
        *,
        info: bytes = b"",
        aad: bytes = b"",
        ephemeral_private_key: bytes | None = None,
    ) -> SealedBox:
        """Encrypt plaintext using RFC 9180 HPKE Base Mode."""
        return hpke_seal_base(
            recipient_public_key,
            plaintext,
            info=info,
            aad=aad,
            ephemeral_private_key=ephemeral_private_key,
        )

    @staticmethod
    def hpke_open(
        recipient_private_key: bytes,
        enc: bytes,
        ciphertext: bytes,
        *,
        info: bytes = b"",
        aad: bytes = b"",
    ) -> bytes:
        """Decrypt ciphertext using RFC 9180 HPKE Base Mode."""
        return hpke_open_base(
            recipient_private_key,
            enc,
            ciphertext,
            info=info,
            aad=aad,
        )

    @staticmethod
    def secretstream_create_key() -> bytearray:
        """Generate a cryptographically secure key for SecretStream."""
        return random_key()

    @staticmethod
    def secretstream_push_stream(key: bytes | bytearray) -> PushStream:
        """Create a SecretStream push stream."""
        return PushStream(key)

    @staticmethod
    def secretstream_pull_all(
        key: bytes, header: bytes, chunks: List[EncryptedChunk]
    ) -> List[bytes]:
        """Decrypt all SecretStream chunks."""
        return pull_all(key, header, chunks)


__all__ = [
    "CryptoEngine",
    "EncryptedChunk",
    "HpkeError",
    "PushStream",
    "SealedBox",
    "SecretStreamError",
    "hpke_generate_key_pair",
    "hpke_open_base",
    "hpke_seal_base",
    "memzero",
    "pull_all",
    "random_key",
]
