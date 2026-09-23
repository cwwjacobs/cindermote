"""Canonical JSON for Cindermote signed documents.

Cindermote contracts intentionally forbid floating-point values.  On that
restricted JSON domain, this encoder emits RFC 8785-compatible bytes while
rejecting values that would invoke platform-dependent number formatting.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

MAX_SAFE_INTEGER = (1 << 53) - 1


class CanonicalizationError(ValueError):
    pass


def _validate(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool)):
        if isinstance(value, str):
            try:
                value.encode("utf-8", "strict")
            except UnicodeEncodeError as exc:
                raise CanonicalizationError(f"{path}: invalid Unicode scalar value") from exc
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise CanonicalizationError(f"{path}: integer outside exact JSON number range")
        return
    if isinstance(value, float):
        raise CanonicalizationError(f"{path}: floating-point values are forbidden")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"{path}: object key is not a string")
            _validate(key, f"{path}.<key>")
            _validate(item, f"{path}.{key}")
        return
    raise CanonicalizationError(f"{path}: unsupported JSON type {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    _validate(value)
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise CanonicalizationError("value is not canonical JSON") from exc
    return encoded


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()
