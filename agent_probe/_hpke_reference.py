"""RFC 9180 HPKE base mode for one-shot CEK wrapping.

Suite:
  DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305
  KEM 0x0020, KDF 0x0001, AEAD 0x0003
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

KEM_ID = 0x0020
KDF_ID = 0x0001
AEAD_ID = 0x0003
NH = 32
NK = 32
NN = 12
VERSION_LABEL = b"HPKE-v1"
KEM_SUITE_ID = b"KEM" + KEM_ID.to_bytes(2, "big")
SUITE_ID = b"HPKE" + KEM_ID.to_bytes(2, "big") + KDF_ID.to_bytes(2, "big") + AEAD_ID.to_bytes(2, "big")


class HpkeError(ValueError):
    pass


def _extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt or b"\x00" * NH, ikm, hashlib.sha256).digest()


def _expand(prk: bytes, info: bytes, length: int) -> bytes:
    if not 0 <= length <= 255 * NH:
        raise HpkeError("HKDF output length is invalid")
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        output.extend(previous)
        counter += 1
    return bytes(output[:length])


def _labeled_extract(suite_id: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return _extract(salt, VERSION_LABEL + suite_id + label + ikm)


def _labeled_expand(suite_id: bytes, prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
    labeled_info = length.to_bytes(2, "big") + VERSION_LABEL + suite_id + label + info
    return _expand(prk, labeled_info, length)


def _public_bytes(key: x25519.X25519PublicKey) -> bytes:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _private_bytes(key: x25519.X25519PrivateKey) -> bytes:
    return key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def generate_key_pair() -> tuple[bytes, bytes]:
    private = x25519.X25519PrivateKey.generate()
    return _private_bytes(private), _public_bytes(private.public_key())


def _extract_and_expand(dh: bytes, kem_context: bytes) -> bytes:
    eae_prk = _labeled_extract(KEM_SUITE_ID, b"", b"eae_prk", dh)
    return _labeled_expand(KEM_SUITE_ID, eae_prk, b"shared_secret", kem_context, NH)


def _key_schedule(shared_secret: bytes, info: bytes) -> tuple[bytes, bytes]:
    psk_id_hash = _labeled_extract(SUITE_ID, b"", b"psk_id_hash", b"")
    info_hash = _labeled_extract(SUITE_ID, b"", b"info_hash", info)
    context = b"\x00" + psk_id_hash + info_hash  # mode_base
    secret = _labeled_extract(SUITE_ID, shared_secret, b"secret", b"")
    key = _labeled_expand(SUITE_ID, secret, b"key", context, NK)
    base_nonce = _labeled_expand(SUITE_ID, secret, b"base_nonce", context, NN)
    return key, base_nonce


@dataclass(frozen=True)
class SealedBox:
    enc: bytes
    ciphertext: bytes


def seal_base(
    recipient_public_key: bytes,
    plaintext: bytes,
    *,
    info: bytes,
    aad: bytes,
    ephemeral_private_key: bytes | None = None,
) -> SealedBox:
    if len(recipient_public_key) != 32:
        raise HpkeError("recipient X25519 public key must be 32 bytes")
    try:
        recipient = x25519.X25519PublicKey.from_public_bytes(recipient_public_key)
        ephemeral = (
            x25519.X25519PrivateKey.from_private_bytes(ephemeral_private_key)
            if ephemeral_private_key is not None
            else x25519.X25519PrivateKey.generate()
        )
        enc = _public_bytes(ephemeral.public_key())
        dh = ephemeral.exchange(recipient)
    except (ValueError, TypeError) as exc:
        raise HpkeError("invalid X25519 key material") from exc
    shared_secret = _extract_and_expand(dh, enc + recipient_public_key)
    key, nonce = _key_schedule(shared_secret, info)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    return SealedBox(enc=enc, ciphertext=ciphertext)


def open_base(
    recipient_private_key: bytes,
    enc: bytes,
    ciphertext: bytes,
    *,
    info: bytes,
    aad: bytes,
) -> bytes:
    if len(recipient_private_key) != 32 or len(enc) != 32:
        raise HpkeError("X25519 private key and encapsulated key must be 32 bytes")
    try:
        recipient_private = x25519.X25519PrivateKey.from_private_bytes(recipient_private_key)
        ephemeral_public = x25519.X25519PublicKey.from_public_bytes(enc)
        recipient_public = _public_bytes(recipient_private.public_key())
        dh = recipient_private.exchange(ephemeral_public)
        shared_secret = _extract_and_expand(dh, enc + recipient_public)
        key, nonce = _key_schedule(shared_secret, info)
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
    except Exception as exc:
        raise HpkeError("HPKE open failed") from exc
