"""Cross-validation and compatibility tests for Cindermote crypto wrapper."""

from __future__ import annotations

import sys
from pathlib import Path
import pytest

THIS_FILE = Path(__file__).resolve()
PROJECT_DIR = THIS_FILE.parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from agent_probe._hpke_reference import open_base as ref_open_base, seal_base as ref_seal_base
from agent_probe._secretstream_reference import (
    PushStream as RefPushStream,
    pull_all as ref_pull_all,
    random_key as ref_random_key,
)
from agent_probe.crypto import CryptoEngine
from agent_probe.hpke import HpkeError, generate_key_pair, open_base, seal_base
from agent_probe.secretstream import SecretStreamError, PushStream, memzero, pull_all, random_key


def test_hpke_seal_and_open_roundtrip():
    """HPKE seal_base and open_base roundtrip correctly."""
    priv, pub = generate_key_pair()
    plaintext = b"top secret evidence payload 12345"
    info = b"cindermote-test-info"
    aad = b"cindermote-test-aad"

    box = seal_base(pub, plaintext, info=info, aad=aad)
    decrypted = open_base(priv, box.enc, box.ciphertext, info=info, aad=aad)

    assert decrypted == plaintext


def test_hpke_cross_validation_with_reference():
    """CryptoEngine HPKE seal is decryptable by reference implementation and vice-versa."""
    priv, pub = CryptoEngine.generate_hpke_keypair()
    plaintext = b"cross validation payload"
    info = b"info"
    aad = b"aad"

    # 1. Engine seal -> Ref open
    box1 = CryptoEngine.hpke_seal(pub, plaintext, info=info, aad=aad)
    dec1 = ref_open_base(priv, box1.enc, box1.ciphertext, info=info, aad=aad)
    assert dec1 == plaintext

    # 2. Ref seal -> Engine open
    box2 = ref_seal_base(pub, plaintext, info=info, aad=aad)
    dec2 = CryptoEngine.hpke_open(priv, box2.enc, box2.ciphertext, info=info, aad=aad)
    assert dec2 == plaintext


def test_hpke_tampered_ciphertext_fails():
    """HPKE open raises HpkeError when ciphertext or AAD is tampered."""
    priv, pub = generate_key_pair()
    plaintext = b"unaltered message"
    box = seal_base(pub, plaintext, info=b"info", aad=b"aad")

    # Tamper ciphertext
    tampered_ct = bytearray(box.ciphertext)
    tampered_ct[0] ^= 0xFF

    with pytest.raises(HpkeError):
        open_base(priv, box.enc, bytes(tampered_ct), info=b"info", aad=b"aad")

    # Tamper AAD
    with pytest.raises(HpkeError):
        open_base(priv, box.enc, box.ciphertext, info=b"info", aad=b"wrong-aad")


def test_secretstream_roundtrip_and_cross_validation():
    """SecretStream push and pull roundtrip and cross-validate with reference."""
    key = random_key()
    stream = PushStream(key)

    chunk1 = stream.push(b"chunk 1 data", aad=b"seq0", final=False)
    chunk2 = stream.push(b"chunk 2 final data", aad=b"seq1", final=True)

    # Decrypt with wrapper pull_all
    decrypted = pull_all(bytes(key), stream.header, [chunk1, chunk2])
    assert decrypted == [b"chunk 1 data", b"chunk 2 final data"]

    # Cross-decrypt with reference pull_all
    decrypted_ref = ref_pull_all(bytes(key), stream.header, [chunk1, chunk2])
    assert decrypted_ref == [b"chunk 1 data", b"chunk 2 final data"]

    memzero(key)
    assert key == bytearray(len(key))


def test_secretstream_out_of_order_chunk_fails():
    """SecretStream pull_all raises SecretStreamError when chunks are out of order."""
    key = random_key()
    stream = PushStream(key)

    chunk1 = stream.push(b"chunk 1", aad=b"seq0", final=False)
    chunk2 = stream.push(b"chunk 2", aad=b"seq1", final=True)

    with pytest.raises(SecretStreamError):
        pull_all(bytes(key), stream.header, [chunk2, chunk1])


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
