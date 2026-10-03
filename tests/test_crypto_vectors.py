"""Known-answer and interoperability tests for the evidence-encryption modules.

``agent_probe/hpke.py`` is a 140-line implementation of RFC 9180 base mode on
PyCA primitives. A round-trip test cannot show that such code is correct, so
these tests pin it to a published vector and to PyCA's independent HPKE.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from agent_probe import hpke as hpke_module  # noqa: E402
from agent_probe.crypto import CryptoEngine  # noqa: E402
from agent_probe.hpke import HpkeError, generate_key_pair, open_base, seal_base  # noqa: E402
from agent_probe.secretstream import (  # noqa: E402
    EncryptedChunk,
    PushStream,
    SecretStreamError,
    memzero,
    pull_all,
    random_key,
)

h = bytes.fromhex

# DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305; base mode; first
# encryption. This is the vector published as RFC 9180 Appendix A.2.1. The RFC
# text was not reachable from the development sandbox, so the values were
# confirmed by recomputation (both directions below reproduce every byte) and by
# interoperability with PyCA's independent implementation.
A21_INFO = h("4f6465206f6e2061204772656369616e2055726e")
A21_SK_EM = h("f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600")
A21_PK_EM = h("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a")
A21_SK_RM = h("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb")
A21_PK_RM = h("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a")
A21_SHARED_SECRET = h("0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7")
A21_KEY = h("ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91")
A21_BASE_NONCE = h("5c4d98150661b848853b547f")
A21_AAD = h("436f756e742d30")
A21_PLAINTEXT = h("4265617574792069732074727574682c20747275746820626561757479")
A21_CIPHERTEXT = h(
    "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28"
)


def test_rfc9180_a21_seal_reproduces_the_published_vector() -> None:
    box = seal_base(
        A21_PK_RM, A21_PLAINTEXT, info=A21_INFO, aad=A21_AAD, ephemeral_private_key=A21_SK_EM
    )
    assert box.enc == A21_PK_EM
    assert box.ciphertext == A21_CIPHERTEXT


def test_rfc9180_a21_open_recovers_the_published_plaintext() -> None:
    assert open_base(A21_SK_RM, A21_PK_EM, A21_CIPHERTEXT, info=A21_INFO, aad=A21_AAD) == A21_PLAINTEXT


def test_rfc9180_a21_key_schedule_intermediates() -> None:
    from cryptography.hazmat.primitives.asymmetric import x25519

    ephemeral = x25519.X25519PrivateKey.from_private_bytes(A21_SK_EM)
    dh = ephemeral.exchange(x25519.X25519PublicKey.from_public_bytes(A21_PK_RM))
    shared_secret = hpke_module._extract_and_expand(dh, A21_PK_EM + A21_PK_RM)
    key, base_nonce = hpke_module._key_schedule(shared_secret, A21_INFO)
    assert shared_secret == A21_SHARED_SECRET
    assert key == A21_KEY
    assert base_nonce == A21_BASE_NONCE


@pytest.mark.parametrize(
    "mutation",
    ["ciphertext", "aad", "info", "enc", "recipient_key"],
)
def test_hpke_rejects_every_kind_of_mismatch(mutation: str) -> None:
    private, public = generate_key_pair()
    box = seal_base(public, b"payload", info=b"info", aad=b"aad")
    kwargs = {"info": b"info", "aad": b"aad"}
    ciphertext, enc, key = box.ciphertext, box.enc, private
    if mutation == "ciphertext":
        ciphertext = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
    elif mutation == "aad":
        kwargs["aad"] = b"other"
    elif mutation == "info":
        kwargs["info"] = b"other"
    elif mutation == "enc":
        enc = bytes([enc[0] ^ 1]) + enc[1:]
    elif mutation == "recipient_key":
        key, _ = generate_key_pair()
    with pytest.raises(HpkeError):
        open_base(key, enc, ciphertext, **kwargs)


@pytest.mark.parametrize("length", [0, 31, 33])
def test_hpke_rejects_wrong_length_keys(length: int) -> None:
    with pytest.raises(HpkeError):
        seal_base(b"\x01" * length, b"x", info=b"", aad=b"")
    with pytest.raises(HpkeError):
        open_base(b"\x01" * length, b"\x02" * 32, b"c" * 32, info=b"", aad=b"")


def test_hpke_interoperates_with_pycryptography_in_both_directions() -> None:
    """Seal with this code and open with PyCA, and the reverse (empty AAD)."""

    pycryptography_hpke = pytest.importorskip(
        "cryptography.hazmat.primitives.hpke",
        reason="installed cryptography release has no HPKE module",
    )
    from cryptography.hazmat.primitives.asymmetric import x25519

    suite = pycryptography_hpke.Suite(
        pycryptography_hpke.KEM.X25519,
        pycryptography_hpke.KDF.HKDF_SHA256,
        pycryptography_hpke.AEAD.CHACHA20_POLY1305,
    )
    for round_number in range(5):
        recipient = x25519.X25519PrivateKey.generate()
        private_raw = recipient.private_bytes_raw()
        public_raw = recipient.public_key().public_bytes_raw()
        plaintext = f"interop payload {round_number}".encode()
        info = f"info-{round_number}".encode()

        box = seal_base(public_raw, plaintext, info=info, aad=b"")
        assert suite.decrypt(box.enc + box.ciphertext, recipient, info=info) == plaintext

        wire = suite.encrypt(plaintext, recipient.public_key(), info=info)
        assert open_base(private_raw, wire[:32], wire[32:], info=info, aad=b"") == plaintext


def test_crypto_engine_facade_matches_the_underlying_modules() -> None:
    private, public = CryptoEngine.generate_hpke_keypair()
    box = CryptoEngine.hpke_seal(public, b"cek", info=b"i", aad=b"a")
    assert open_base(private, box.enc, box.ciphertext, info=b"i", aad=b"a") == b"cek"
    assert CryptoEngine.hpke_open(private, box.enc, box.ciphertext, info=b"i", aad=b"a") == b"cek"

    key = CryptoEngine.secretstream_create_key()
    stream = CryptoEngine.secretstream_push_stream(key)
    chunk = stream.push(b"data", aad=b"a", final=True)
    assert CryptoEngine.secretstream_pull_all(bytes(key), stream.header, [chunk]) == [b"data"]
    memzero(key)
    assert key == bytearray(len(key))


# --- secretstream misuse resistance ---------------------------------------------


def _stream(count: int = 3) -> tuple[bytearray, PushStream, list[EncryptedChunk]]:
    key = random_key()
    stream = PushStream(key)
    chunks = [
        stream.push(f"record {index}".encode(), aad=f"aad-{index}".encode(), final=index == count - 1)
        for index in range(count)
    ]
    return key, stream, chunks


def test_secretstream_round_trip() -> None:
    key, stream, chunks = _stream()
    assert pull_all(bytes(key), stream.header, chunks) == [b"record 0", b"record 1", b"record 2"]


def _stream_cases() -> dict:
    """Valid stream plus one corrupted variant per way a transcript can be attacked."""

    key, stream, chunks = _stream()

    def replaced(index: int, **changes: object) -> list[EncryptedChunk]:
        original = chunks[index]
        fields = {
            "sequence": original.sequence,
            "aad": original.aad,
            "ciphertext": original.ciphertext,
            "final": original.final,
        }
        fields.update(changes)
        candidate = list(chunks)
        candidate[index] = EncryptedChunk(**fields)  # type: ignore[arg-type]
        return candidate

    flipped = bytearray(chunks[1].ciphertext)
    flipped[0] ^= 1
    header = bytes(stream.header)
    return {
        "missing final chunk": (bytes(key), header, chunks[:-1]),
        "dropped middle chunk": (bytes(key), header, [chunks[0], chunks[2]]),
        "reordered": (bytes(key), header, [chunks[1], chunks[0], chunks[2]]),
        "replayed chunk": (bytes(key), header, [chunks[0], chunks[0], chunks[1], chunks[2]]),
        "trailing data after final": (bytes(key), header, chunks + [chunks[0]]),
        "empty stream": (bytes(key), header, []),
        "aad changed": (bytes(key), header, replaced(1, aad=b"different")),
        "ciphertext flipped": (bytes(key), header, replaced(1, ciphertext=bytes(flipped))),
        "final flag cleared": (bytes(key), header, replaced(2, final=False)),
        "wrong key": (bytes(random_key()), header, chunks),
        "wrong header": (bytes(key), bytes([header[0] ^ 1]) + header[1:], chunks),
    }


_CASES = _stream_cases()


@pytest.mark.parametrize("case", sorted(_CASES))
def test_secretstream_rejects_every_corrupted_transcript(case: str) -> None:
    key, header, chunks = _CASES[case]
    with pytest.raises(SecretStreamError):
        pull_all(key, header, chunks)


def test_secretstream_refuses_use_after_final_and_oversized_chunks() -> None:
    key = random_key()
    stream = PushStream(key)
    stream.push(b"last", aad=b"", final=True)
    with pytest.raises(SecretStreamError):
        stream.push(b"more", aad=b"")
    with pytest.raises(SecretStreamError):
        PushStream(random_key()).push(b"x" * (64 * 1024 + 1), aad=b"")
    with pytest.raises(SecretStreamError):
        PushStream(b"short")
