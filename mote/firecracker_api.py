#!/usr/bin/env python3
"""Bounded native HTTP transport for the Firecracker API socket.

Firecracker exposes an HTTP/1.1 API over an AF_UNIX socket.  This module keeps
that control channel dependency-free and deliberately small: one request per
connection, JSON request bodies only, explicit expected status codes, and hard
limits around every byte read from the monitor.

This is a control-plane client, not a general-purpose HTTP implementation.  It
rejects response features Firecracker does not need (informational responses,
transfer encodings, compression, duplicate headers, and ambiguous framing).
"""

from __future__ import annotations

import json
import math
import os
import re
import socket
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Mapping


_ENDPOINT_SEGMENT = re.compile(r"^[A-Za-z0-9_~.-]+$")
_HEADER_NAME = re.compile(rb"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_STATUS_LINE = re.compile(rb"^HTTP/(1[.]0|1[.]1) ([0-9]{3})(?: ([\x20-\x7e]*))?$")
_CONTENT_LENGTH = re.compile(r"^[0-9]+$")

_MAX_UNIX_PATH_BYTES = 107  # Linux sockaddr_un.sun_path, excluding trailing NUL.
_MAX_ENDPOINT_BYTES = 2048
_MAX_CONFIGURED_BODY_BYTES = 64 * 1024 * 1024
_MAX_CONFIGURED_HEADER_BYTES = 256 * 1024
_MAX_TIMEOUT_SEC = 60.0
_MAX_JSON_NESTING = 64


class FirecrackerApiError(RuntimeError):
    """Base class for Firecracker API control-channel failures."""


class FirecrackerTransportError(FirecrackerApiError):
    """The Unix socket could not be reached or failed during I/O."""


class FirecrackerTimeoutError(FirecrackerTransportError):
    """The request exceeded its single absolute deadline."""


class FirecrackerProtocolError(FirecrackerApiError):
    """The peer returned a malformed or ambiguously framed HTTP response."""


class FirecrackerResponseTooLarge(FirecrackerProtocolError):
    """A peer response exceeded a configured byte limit."""


class FirecrackerJsonError(FirecrackerProtocolError):
    """A JSON request or response failed strict validation."""


class FirecrackerStatusError(FirecrackerApiError):
    """The monitor returned a well-formed response with an unexpected status."""

    def __init__(
        self,
        response: "FirecrackerResponse",
        expected_statuses: tuple[int, ...],
    ) -> None:
        self.response = response
        self.expected_statuses = expected_statuses
        expected = ", ".join(str(value) for value in expected_statuses)
        detail = _safe_body_summary(response.body)
        suffix = f": {detail}" if detail else ""
        super().__init__(
            f"Firecracker API returned HTTP {response.status}; expected {expected}{suffix}"
        )

    @property
    def fault_message(self) -> str | None:
        """Return Firecracker's bounded ``fault_message`` value when available."""

        try:
            value = self.response.json(expected_type=dict)
        except FirecrackerJsonError:
            return None
        message = value.get("fault_message")
        return message if isinstance(message, str) else None


@dataclass(frozen=True)
class FirecrackerResponse:
    """A completely read, bounded Firecracker HTTP response."""

    status: int
    reason: str
    headers: Mapping[str, str]
    body: bytes

    def json(
        self,
        *,
        expected_type: type[dict] | type[list] = dict,
        require_content_type: bool = True,
    ) -> dict[str, Any] | list[Any]:
        """Decode a non-empty response body as strict UTF-8 JSON.

        Duplicate object keys, non-finite numbers, a wrong top-level type, and
        non-JSON content types are rejected rather than normalized silently.
        """

        if not self.body:
            raise FirecrackerJsonError("Firecracker response body is empty")
        if require_content_type:
            content_type = self.headers.get("content-type", "")
            media_type = content_type.split(";", 1)[0].strip().lower()
            if media_type != "application/json":
                raise FirecrackerJsonError(
                    "Firecracker response Content-Type is not application/json"
                )
        value = _decode_json(self.body)
        if not isinstance(value, expected_type):
            raise FirecrackerJsonError(
                f"Firecracker JSON response must be a {expected_type.__name__}"
            )
        return value


def build_endpoint(*segments: str) -> str:
    """Construct an API endpoint without allowing path delimiter injection."""

    if not segments:
        return "/"
    checked: list[str] = []
    for segment in segments:
        if not isinstance(segment, str):
            raise TypeError("Firecracker endpoint segments must be strings")
        if segment in {"", ".", ".."} or _ENDPOINT_SEGMENT.fullmatch(segment) is None:
            raise ValueError(f"unsafe Firecracker endpoint segment: {segment!r}")
        checked.append(segment)
    endpoint = "/" + "/".join(checked)
    return _validate_endpoint(endpoint)


class FirecrackerApiClient:
    """Single-request Unix-socket client for the Firecracker monitor API."""

    def __init__(
        self,
        socket_path: str | os.PathLike[str],
        *,
        timeout_sec: float = 2.0,
        max_request_body_bytes: int = 1024 * 1024,
        max_response_body_bytes: int = 1024 * 1024,
        max_header_bytes: int = 32 * 1024,
    ) -> None:
        self.socket_path = _validate_socket_path(socket_path)
        self.timeout_sec = _validate_timeout(timeout_sec)
        self.max_request_body_bytes = _validate_limit(
            "max_request_body_bytes",
            max_request_body_bytes,
            _MAX_CONFIGURED_BODY_BYTES,
        )
        self.max_response_body_bytes = _validate_limit(
            "max_response_body_bytes",
            max_response_body_bytes,
            _MAX_CONFIGURED_BODY_BYTES,
        )
        self.max_header_bytes = _validate_limit(
            "max_header_bytes",
            max_header_bytes,
            _MAX_CONFIGURED_HEADER_BYTES,
        )

    def request(
        self,
        method: str,
        endpoint: str,
        *,
        expected_status: int | Iterable[int],
        payload: dict[str, Any] | None = None,
    ) -> FirecrackerResponse:
        """Send one bounded request and require an explicitly named status."""

        checked_method = _validate_method(method)
        checked_endpoint = _validate_endpoint(endpoint)
        expected_statuses = _normalize_expected_status(expected_status)
        if checked_method == "GET" and payload is not None:
            raise FirecrackerJsonError("GET requests must not contain a JSON payload")
        if checked_method in {"PUT", "PATCH"} and payload is None:
            raise FirecrackerJsonError(f"{checked_method} requests require a JSON payload")
        body = self._encode_payload(payload)
        request = self._build_request(checked_method, checked_endpoint, body, payload)
        deadline = time.monotonic() + self.timeout_sec

        sock = self._connect(deadline)
        try:
            self._send_all(sock, request, deadline)
            response = self._read_response(sock, checked_method, deadline)
        finally:
            sock.close()

        if response.status not in expected_statuses:
            raise FirecrackerStatusError(response, expected_statuses)
        return response

    def request_json(
        self,
        method: str,
        endpoint: str,
        *,
        expected_status: int | Iterable[int],
        payload: dict[str, Any] | None = None,
        response_type: type[dict] | type[list] = dict,
    ) -> dict[str, Any] | list[Any] | None:
        """Send JSON and decode JSON, allowing empty bodies only for 204/205."""

        response = self.request(
            method,
            endpoint,
            expected_status=expected_status,
            payload=payload,
        )
        if not response.body:
            if response.status in {204, 205}:
                return None
            raise FirecrackerJsonError("Firecracker JSON response body is empty")
        return response.json(expected_type=response_type)

    def get_json(
        self,
        endpoint: str,
        *,
        expected_status: int | Iterable[int] = 200,
        response_type: type[dict] | type[list] = dict,
    ) -> dict[str, Any] | list[Any]:
        value = self.request_json(
            "GET",
            endpoint,
            expected_status=expected_status,
            response_type=response_type,
        )
        if value is None:  # A 204 is possible only if the caller explicitly expected it.
            raise FirecrackerJsonError("GET response did not contain JSON")
        return value

    def put_json(
        self,
        endpoint: str,
        payload: dict[str, Any],
        *,
        expected_status: int | Iterable[int] = 204,
        response_type: type[dict] | type[list] = dict,
    ) -> dict[str, Any] | list[Any] | None:
        return self.request_json(
            "PUT",
            endpoint,
            expected_status=expected_status,
            payload=payload,
            response_type=response_type,
        )

    def patch_json(
        self,
        endpoint: str,
        payload: dict[str, Any],
        *,
        expected_status: int | Iterable[int] = 204,
        response_type: type[dict] | type[list] = dict,
    ) -> dict[str, Any] | list[Any] | None:
        return self.request_json(
            "PATCH",
            endpoint,
            expected_status=expected_status,
            payload=payload,
            response_type=response_type,
        )

    def _encode_payload(self, payload: dict[str, Any] | None) -> bytes:
        if payload is None:
            return b""
        if not isinstance(payload, dict):
            raise FirecrackerJsonError("Firecracker request payload must be a JSON object")
        _validate_json_value(payload)
        try:
            encoded = json.dumps(
                payload,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeError) as exc:
            raise FirecrackerJsonError(f"invalid Firecracker request JSON: {exc}") from exc
        if len(encoded) > self.max_request_body_bytes:
            raise FirecrackerJsonError(
                "Firecracker request JSON exceeds max_request_body_bytes"
            )
        return encoded

    @staticmethod
    def _build_request(
        method: str,
        endpoint: str,
        body: bytes,
        payload: dict[str, Any] | None,
    ) -> bytes:
        lines = [
            f"{method} {endpoint} HTTP/1.1",
            "Host: localhost",
            "Accept: application/json",
            "Connection: close",
            f"Content-Length: {len(body)}",
        ]
        if payload is not None:
            lines.append("Content-Type: application/json")
        return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body

    def _connect(self, deadline: float) -> socket.socket:
        try:
            socket_stat = os.lstat(self.socket_path)
        except OSError as exc:
            raise FirecrackerTransportError(
                f"Firecracker API socket is unavailable: {self.socket_path}"
            ) from exc
        if stat.S_ISLNK(socket_stat.st_mode):
            raise FirecrackerTransportError("refusing a symlink Firecracker API socket")
        if not stat.S_ISSOCK(socket_stat.st_mode):
            raise FirecrackerTransportError("Firecracker API path is not a Unix socket")

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self._set_deadline(sock, deadline, "connect")
            sock.connect(str(self.socket_path))
        except socket.timeout as exc:
            sock.close()
            raise FirecrackerTimeoutError(
                "Firecracker API connect exceeded the request deadline"
            ) from exc
        except OSError as exc:
            sock.close()
            raise FirecrackerTransportError(
                f"could not connect to Firecracker API socket: {self.socket_path}"
            ) from exc
        return sock

    def _send_all(self, sock: socket.socket, data: bytes, deadline: float) -> None:
        view = memoryview(data)
        while view:
            self._set_deadline(sock, deadline, "send")
            try:
                sent = sock.send(view)
            except socket.timeout as exc:
                raise FirecrackerTimeoutError(
                    "Firecracker API send exceeded the request deadline"
                ) from exc
            except OSError as exc:
                raise FirecrackerTransportError("Firecracker API request send failed") from exc
            if sent <= 0:
                raise FirecrackerTransportError("Firecracker API socket closed during send")
            view = view[sent:]

    def _recv(self, sock: socket.socket, count: int, deadline: float) -> bytes:
        self._set_deadline(sock, deadline, "receive")
        try:
            return sock.recv(count)
        except socket.timeout as exc:
            raise FirecrackerTimeoutError(
                "Firecracker API receive exceeded the request deadline"
            ) from exc
        except OSError as exc:
            raise FirecrackerTransportError("Firecracker API response receive failed") from exc

    @staticmethod
    def _set_deadline(sock: socket.socket, deadline: float, operation: str) -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise FirecrackerTimeoutError(
                f"Firecracker API {operation} exceeded the request deadline"
            )
        sock.settimeout(remaining)

    def _read_response(
        self,
        sock: socket.socket,
        request_method: str,
        deadline: float,
    ) -> FirecrackerResponse:
        buffer = bytearray()
        delimiter = b"\r\n\r\n"
        while True:
            boundary = buffer.find(delimiter)
            if boundary >= 0:
                break
            allowance = self.max_header_bytes + 1 - len(buffer)
            if allowance <= 0:
                raise FirecrackerResponseTooLarge(
                    "Firecracker response headers exceed max_header_bytes"
                )
            chunk = self._recv(sock, min(4096, allowance), deadline)
            if not chunk:
                raise FirecrackerProtocolError(
                    "Firecracker API socket closed before response headers completed"
                )
            buffer.extend(chunk)

        header_size = boundary + len(delimiter)
        if header_size > self.max_header_bytes:
            raise FirecrackerResponseTooLarge(
                "Firecracker response headers exceed max_header_bytes"
            )
        head = bytes(buffer[:boundary])
        buffered_body = bytes(buffer[header_size:])
        status, reason, headers = _parse_response_head(head)

        if 100 <= status < 200:
            raise FirecrackerProtocolError(
                "informational Firecracker responses are not supported"
            )
        if "transfer-encoding" in headers:
            raise FirecrackerProtocolError(
                "Firecracker response Transfer-Encoding is not accepted"
            )
        content_encoding = headers.get("content-encoding", "identity").strip().lower()
        if content_encoding not in {"", "identity"}:
            raise FirecrackerProtocolError(
                "compressed Firecracker responses are not accepted"
            )

        content_length = _parse_content_length(headers.get("content-length"))
        no_body = request_method == "HEAD" or status in {204, 205, 304}
        if no_body:
            if content_length not in {None, 0} or buffered_body:
                raise FirecrackerProtocolError(
                    f"HTTP {status} Firecracker response illegally contains a body"
                )
            body = b""
        elif content_length is not None:
            if content_length > self.max_response_body_bytes:
                raise FirecrackerResponseTooLarge(
                    "Firecracker response body exceeds max_response_body_bytes"
                )
            if len(buffered_body) > content_length:
                raise FirecrackerProtocolError(
                    "Firecracker response contains bytes beyond Content-Length"
                )
            body_buffer = bytearray(buffered_body)
            while len(body_buffer) < content_length:
                remaining = content_length - len(body_buffer)
                chunk = self._recv(sock, min(65536, remaining), deadline)
                if not chunk:
                    raise FirecrackerProtocolError(
                        "Firecracker response ended before Content-Length bytes arrived"
                    )
                body_buffer.extend(chunk)
            body = bytes(body_buffer)
        else:
            body_buffer = bytearray(buffered_body)
            if len(body_buffer) > self.max_response_body_bytes:
                raise FirecrackerResponseTooLarge(
                    "Firecracker response body exceeds max_response_body_bytes"
                )
            while True:
                allowance = self.max_response_body_bytes + 1 - len(body_buffer)
                if allowance <= 0:
                    raise FirecrackerResponseTooLarge(
                        "Firecracker response body exceeds max_response_body_bytes"
                    )
                chunk = self._recv(sock, min(65536, allowance), deadline)
                if not chunk:
                    break
                body_buffer.extend(chunk)
                if len(body_buffer) > self.max_response_body_bytes:
                    raise FirecrackerResponseTooLarge(
                        "Firecracker response body exceeds max_response_body_bytes"
                    )
            body = bytes(body_buffer)

        return FirecrackerResponse(
            status=status,
            reason=reason,
            headers=MappingProxyType(headers),
            body=body,
        )


# Concise spelling for callers that treat this object as the API facade.
FirecrackerAPI = FirecrackerApiClient


def _validate_socket_path(path: str | os.PathLike[str]) -> Path:
    try:
        raw = os.fspath(path)
    except TypeError as exc:
        raise TypeError("Firecracker API socket path must be path-like") from exc
    if isinstance(raw, bytes):
        raise TypeError("Firecracker API socket path must be text")
    if "\0" in raw:
        raise ValueError("Firecracker API socket path contains a NUL byte")
    if any(ord(character) < 32 or ord(character) == 127 for character in raw):
        raise ValueError("Firecracker API socket path contains a control character")
    if (
        raw == "/"
        or raw.startswith("//")
        or raw.endswith("/")
        or any(part in {"", ".", ".."} for part in raw.split("/")[1:])
    ):
        raise ValueError("Firecracker API socket path must be canonical")
    candidate = Path(raw)
    if not candidate.is_absolute():
        raise ValueError("Firecracker API socket path must be absolute")
    try:
        encoded = os.fsencode(raw)
    except UnicodeError as exc:
        raise ValueError("Firecracker API socket path is not filesystem-encodable") from exc
    if len(encoded) > _MAX_UNIX_PATH_BYTES:
        raise ValueError("Firecracker API socket path is too long for AF_UNIX")
    return candidate


def _validate_timeout(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("timeout_sec must be a number")
    timeout = float(value)
    if not math.isfinite(timeout) or timeout <= 0 or timeout > _MAX_TIMEOUT_SEC:
        raise ValueError(f"timeout_sec must be within (0, {_MAX_TIMEOUT_SEC}]")
    return timeout


def _validate_limit(name: str, value: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if value <= 0 or value > maximum:
        raise ValueError(f"{name} must be within [1, {maximum}]")
    return value


def _validate_method(method: str) -> str:
    if not isinstance(method, str):
        raise TypeError("Firecracker API method must be a string")
    checked = method.upper()
    if checked not in {"GET", "PUT", "PATCH"}:
        raise ValueError("Firecracker API method must be GET, PUT, or PATCH")
    return checked


def _validate_endpoint(endpoint: str) -> str:
    if not isinstance(endpoint, str):
        raise TypeError("Firecracker API endpoint must be a string")
    try:
        encoded = endpoint.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("Firecracker API endpoint must be ASCII") from exc
    if len(encoded) > _MAX_ENDPOINT_BYTES:
        raise ValueError("Firecracker API endpoint is too long")
    if endpoint == "/":
        return endpoint
    if not endpoint.startswith("/") or endpoint.endswith("/"):
        raise ValueError("Firecracker API endpoint must be an absolute canonical path")
    segments = endpoint[1:].split("/")
    if any(
        segment in {"", ".", ".."} or _ENDPOINT_SEGMENT.fullmatch(segment) is None
        for segment in segments
    ):
        raise ValueError("Firecracker API endpoint contains an unsafe path segment")
    return endpoint


def _normalize_expected_status(value: int | Iterable[int]) -> tuple[int, ...]:
    if isinstance(value, bool):
        raise TypeError("expected_status must contain integer HTTP statuses")
    if isinstance(value, int):
        values = (value,)
    else:
        if isinstance(value, (str, bytes)):
            raise TypeError("expected_status must contain integer HTTP statuses")
        try:
            values = tuple(value)
        except TypeError as exc:
            raise TypeError("expected_status must be an integer or iterable") from exc
    if not values:
        raise ValueError("expected_status must not be empty")
    if any(isinstance(item, bool) or not isinstance(item, int) for item in values):
        raise TypeError("expected_status must contain integer HTTP statuses")
    if any(item < 100 or item > 599 for item in values):
        raise ValueError("expected_status contains an invalid HTTP status")
    return tuple(sorted(set(values)))


def _validate_json_value(
    value: Any,
    path: str = "$",
    *,
    _depth: int = 0,
    _active_containers: set[int] | None = None,
) -> None:
    if _depth > _MAX_JSON_NESTING:
        raise FirecrackerJsonError(
            f"JSON nesting exceeds {_MAX_JSON_NESTING} levels at {path}"
        )
    if value is None or isinstance(value, (bool, str)):
        if isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise FirecrackerJsonError(f"invalid Unicode string at {path}") from exc
        return
    if isinstance(value, int) and not isinstance(value, bool):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise FirecrackerJsonError(f"non-finite number at {path}")
        return
    if isinstance(value, list):
        active = _active_containers if _active_containers is not None else set()
        identity = id(value)
        if identity in active:
            raise FirecrackerJsonError(f"cyclic JSON container at {path}")
        active.add(identity)
        try:
            for index, item in enumerate(value):
                _validate_json_value(
                    item,
                    f"{path}[{index}]",
                    _depth=_depth + 1,
                    _active_containers=active,
                )
        finally:
            active.remove(identity)
        return
    if isinstance(value, dict):
        active = _active_containers if _active_containers is not None else set()
        identity = id(value)
        if identity in active:
            raise FirecrackerJsonError(f"cyclic JSON container at {path}")
        active.add(identity)
        try:
            for key, item in value.items():
                if not isinstance(key, str):
                    raise FirecrackerJsonError(f"non-string object key at {path}")
                _validate_json_value(
                    key,
                    f"{path}.<key>",
                    _depth=_depth + 1,
                    _active_containers=active,
                )
                _validate_json_value(
                    item,
                    f"{path}.<value>",
                    _depth=_depth + 1,
                    _active_containers=active,
                )
        finally:
            active.remove(identity)
        return
    raise FirecrackerJsonError(f"unsupported JSON value at {path}: {type(value).__name__}")


class _DuplicateJsonKey(ValueError):
    pass


def _decode_json(body: bytes) -> Any:
    try:
        text = body.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise FirecrackerJsonError("Firecracker JSON response is not valid UTF-8") from exc

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise _DuplicateJsonKey(key)
            result[key] = value
        return result

    def finite_float(raw: str) -> float:
        value = float(raw)
        if not math.isfinite(value):
            raise ValueError("non-finite JSON number")
        return value

    def reject_constant(raw: str) -> None:
        raise ValueError(f"non-standard JSON constant: {raw}")

    try:
        value = json.loads(
            text,
            object_pairs_hook=object_pairs,
            parse_float=finite_float,
            parse_constant=reject_constant,
        )
    except _DuplicateJsonKey as exc:
        raise FirecrackerJsonError(
            f"Firecracker JSON response contains duplicate key: {exc.args[0]!r}"
        ) from exc
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise FirecrackerJsonError(f"invalid Firecracker JSON response: {exc}") from exc
    _validate_json_value(value)
    return value


def _parse_response_head(head: bytes) -> tuple[int, str, dict[str, str]]:
    lines = head.split(b"\r\n")
    if not lines or not lines[0]:
        raise FirecrackerProtocolError("Firecracker response status line is missing")
    match = _STATUS_LINE.fullmatch(lines[0])
    if match is None:
        raise FirecrackerProtocolError("Firecracker response status line is malformed")
    status = int(match.group(2))
    if status < 100 or status > 599:
        raise FirecrackerProtocolError("Firecracker response status is invalid")
    reason = (match.group(3) or b"").decode("ascii")

    headers: dict[str, str] = {}
    for raw_line in lines[1:]:
        if not raw_line:
            raise FirecrackerProtocolError("Firecracker response contains an empty header line")
        if raw_line[:1] in {b" ", b"\t"}:
            raise FirecrackerProtocolError("folded Firecracker response headers are rejected")
        if b":" not in raw_line:
            raise FirecrackerProtocolError("Firecracker response header is malformed")
        raw_name, raw_value = raw_line.split(b":", 1)
        if _HEADER_NAME.fullmatch(raw_name) is None:
            raise FirecrackerProtocolError("Firecracker response header name is invalid")
        if any(byte < 32 and byte != 9 or byte == 127 for byte in raw_value):
            raise FirecrackerProtocolError("Firecracker response header value is invalid")
        name = raw_name.decode("ascii").lower()
        if name in headers:
            raise FirecrackerProtocolError(
                f"duplicate Firecracker response header is rejected: {name}"
            )
        headers[name] = raw_value.decode("latin-1").strip(" \t")
    return status, reason, headers


def _parse_content_length(raw: str | None) -> int | None:
    if raw is None:
        return None
    if _CONTENT_LENGTH.fullmatch(raw) is None:
        raise FirecrackerProtocolError("Firecracker response Content-Length is invalid")
    try:
        return int(raw, 10)
    except ValueError as exc:
        raise FirecrackerProtocolError(
            "Firecracker response Content-Length is invalid"
        ) from exc


def _safe_body_summary(body: bytes, limit: int = 240) -> str:
    text = body.decode("utf-8", "replace")
    safe = "".join(character if character.isprintable() else " " for character in text)
    safe = " ".join(safe.split())
    if len(safe) > limit:
        return safe[:limit] + "..."
    return safe
