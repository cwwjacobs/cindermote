"""Small ctypes binding for libsodium SecretStream XChaCha20-Poly1305."""

from __future__ import annotations

import ctypes
import ctypes.util
from dataclasses import dataclass


class SecretStreamError(RuntimeError):
    pass


def _library() -> ctypes.CDLL:
    path = ctypes.util.find_library("sodium")
    if not path:
        raise SecretStreamError("libsodium is unavailable")
    lib = ctypes.CDLL(path)
    if lib.sodium_init() < 0:
        raise SecretStreamError("libsodium initialization failed")
    return lib


_LIB = _library()

_LIB.sodium_init.argtypes = []
_LIB.sodium_init.restype = ctypes.c_int
_LIB.randombytes_buf.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
_LIB.randombytes_buf.restype = None
_LIB.sodium_memzero.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
_LIB.sodium_memzero.restype = None
_LIB.crypto_secretstream_xchacha20poly1305_init_push.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
_LIB.crypto_secretstream_xchacha20poly1305_init_push.restype = ctypes.c_int
_LIB.crypto_secretstream_xchacha20poly1305_push.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong),
    ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_ubyte,
]
_LIB.crypto_secretstream_xchacha20poly1305_push.restype = ctypes.c_int
_LIB.crypto_secretstream_xchacha20poly1305_init_pull.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
_LIB.crypto_secretstream_xchacha20poly1305_init_pull.restype = ctypes.c_int
_LIB.crypto_secretstream_xchacha20poly1305_pull.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong), ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p, ctypes.c_ulonglong,
]
_LIB.crypto_secretstream_xchacha20poly1305_pull.restype = ctypes.c_int
_LIB.crypto_secretstream_xchacha20poly1305_statebytes.restype = ctypes.c_size_t
_LIB.crypto_secretstream_xchacha20poly1305_keybytes.restype = ctypes.c_size_t
_LIB.crypto_secretstream_xchacha20poly1305_headerbytes.restype = ctypes.c_size_t
_LIB.crypto_secretstream_xchacha20poly1305_abytes.restype = ctypes.c_size_t

STATE_BYTES = int(_LIB.crypto_secretstream_xchacha20poly1305_statebytes())
KEY_BYTES = int(_LIB.crypto_secretstream_xchacha20poly1305_keybytes())
HEADER_BYTES = int(_LIB.crypto_secretstream_xchacha20poly1305_headerbytes())
ABYTES = int(_LIB.crypto_secretstream_xchacha20poly1305_abytes())
TAG_MESSAGE = 0
TAG_FINAL = 3
MAX_CHUNK_BYTES = 64 * 1024


def random_key() -> bytearray:
    key = bytearray(KEY_BYTES)
    buffer = (ctypes.c_ubyte * KEY_BYTES).from_buffer(key)
    _LIB.randombytes_buf(buffer, KEY_BYTES)
    return key


def memzero(value: bytearray) -> None:
    if not value:
        return
    buffer = (ctypes.c_ubyte * len(value)).from_buffer(value)
    _LIB.sodium_memzero(buffer, len(value))


@dataclass(frozen=True)
class EncryptedChunk:
    sequence: int
    aad: bytes
    ciphertext: bytes
    final: bool


class PushStream:
    def __init__(self, key: bytes | bytearray) -> None:
        if len(key) != KEY_BYTES:
            raise SecretStreamError(f"SecretStream key must be {KEY_BYTES} bytes")
        self._state = ctypes.create_string_buffer(STATE_BYTES)
        self.header = bytes(HEADER_BYTES)
        header = (ctypes.c_ubyte * HEADER_BYTES)()
        key_buffer = (ctypes.c_ubyte * KEY_BYTES).from_buffer_copy(bytes(key))
        result = _LIB.crypto_secretstream_xchacha20poly1305_init_push(
            ctypes.byref(self._state), header, key_buffer
        )
        if result != 0:
            raise SecretStreamError("SecretStream push initialization failed")
        self.header = bytes(header)
        self.sequence = 0
        self.finalized = False

    def push(self, plaintext: bytes, *, aad: bytes, final: bool = False) -> EncryptedChunk:
        if self.finalized:
            raise SecretStreamError("SecretStream is finalized")
        if len(plaintext) > MAX_CHUNK_BYTES:
            raise SecretStreamError("SecretStream plaintext chunk exceeds 64 KiB")
        output = (ctypes.c_ubyte * (len(plaintext) + ABYTES))()
        output_len = ctypes.c_ulonglong()
        message = (ctypes.c_ubyte * len(plaintext)).from_buffer_copy(plaintext) if plaintext else None
        ad = (ctypes.c_ubyte * len(aad)).from_buffer_copy(aad) if aad else None
        tag = TAG_FINAL if final else TAG_MESSAGE
        result = _LIB.crypto_secretstream_xchacha20poly1305_push(
            ctypes.byref(self._state),
            output,
            ctypes.byref(output_len),
            message,
            len(plaintext),
            ad,
            len(aad),
            tag,
        )
        if result != 0:
            raise SecretStreamError("SecretStream push failed")
        chunk = EncryptedChunk(self.sequence, aad, bytes(output[: output_len.value]), final)
        self.sequence += 1
        if final:
            self.finalized = True
            _LIB.sodium_memzero(ctypes.byref(self._state), STATE_BYTES)
        return chunk


def pull_all(key: bytes, header: bytes, chunks: list[EncryptedChunk]) -> list[bytes]:
    if len(key) != KEY_BYTES or len(header) != HEADER_BYTES:
        raise SecretStreamError("invalid SecretStream key or header")
    state = ctypes.create_string_buffer(STATE_BYTES)
    header_buffer = (ctypes.c_ubyte * HEADER_BYTES).from_buffer_copy(header)
    key_buffer = (ctypes.c_ubyte * KEY_BYTES).from_buffer_copy(key)
    if _LIB.crypto_secretstream_xchacha20poly1305_init_pull(ctypes.byref(state), header_buffer, key_buffer) != 0:
        raise SecretStreamError("SecretStream pull initialization failed")
    plaintexts: list[bytes] = []
    saw_final = False
    for expected_sequence, chunk in enumerate(chunks):
        if chunk.sequence != expected_sequence or saw_final:
            raise SecretStreamError("SecretStream sequence is invalid")
        output = (ctypes.c_ubyte * max(1, len(chunk.ciphertext)))()
        output_len = ctypes.c_ulonglong()
        tag = ctypes.c_ubyte()
        ciphertext = (ctypes.c_ubyte * len(chunk.ciphertext)).from_buffer_copy(chunk.ciphertext)
        ad = (ctypes.c_ubyte * len(chunk.aad)).from_buffer_copy(chunk.aad) if chunk.aad else None
        result = _LIB.crypto_secretstream_xchacha20poly1305_pull(
            ctypes.byref(state),
            output,
            ctypes.byref(output_len),
            ctypes.byref(tag),
            ciphertext,
            len(chunk.ciphertext),
            ad,
            len(chunk.aad),
        )
        if result != 0:
            raise SecretStreamError("SecretStream authentication failed")
        is_final = int(tag.value) == TAG_FINAL
        if is_final != chunk.final:
            raise SecretStreamError("SecretStream tag metadata mismatch")
        saw_final = is_final
        plaintexts.append(bytes(output[: output_len.value]))
    if not saw_final:
        raise SecretStreamError("SecretStream final tag is missing")
    return plaintexts
