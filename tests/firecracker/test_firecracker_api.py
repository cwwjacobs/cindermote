#!/usr/bin/env python3
from __future__ import annotations

import json
import socket
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


PROJECT_DIR = Path(__file__).resolve().parents[2]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from mote.firecracker_api import (
    FirecrackerApiClient,
    FirecrackerJsonError,
    FirecrackerProtocolError,
    FirecrackerResponseTooLarge,
    FirecrackerStatusError,
    FirecrackerTimeoutError,
    FirecrackerTransportError,
    build_endpoint,
)


class _MemorySocket:
    """Small socket double that preserves chunking and timeout behavior."""

    def __init__(self, chunks: list[bytes], *, receive_delay: float = 0.0) -> None:
        self.chunks = list(chunks)
        self.receive_delay = receive_delay
        self.timeout: float | None = None
        self.sent = bytearray()
        self.closed = False

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def send(self, data: bytes | memoryview) -> int:
        if self.closed:
            raise OSError("socket is closed")
        raw = bytes(data)
        self.sent.extend(raw)
        return len(raw)

    def recv(self, count: int) -> bytes:
        if self.closed:
            return b""
        if self.receive_delay:
            assert self.timeout is not None
            if self.receive_delay > self.timeout:
                time.sleep(self.timeout)
                raise socket.timeout("scripted receive timeout")
            time.sleep(self.receive_delay)
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if len(chunk) > count:
            self.chunks.insert(0, chunk[count:])
            chunk = chunk[:count]
        return chunk

    def close(self) -> None:
        self.closed = True


class _ConnectedClient(FirecrackerApiClient):
    """Test client whose transport is a one-shot in-memory socket."""

    def __init__(self, connected_socket: _MemorySocket, **kwargs: object) -> None:
        super().__init__("/tmp/cindermote-firecracker-api-unit.socket", **kwargs)
        self._connected_socket: _MemorySocket | None = connected_socket

    def _connect(self, _deadline: float) -> _MemorySocket:  # type: ignore[override]
        if self._connected_socket is None:
            raise AssertionError("test client attempted to reuse a one-shot connection")
        result = self._connected_socket
        self._connected_socket = None
        return result


class _ScriptedServer:
    def __init__(
        self,
        socket_path: Path,
        chunks: list[bytes],
        *,
        delay_before_send: float = 0.0,
        inter_chunk_delay: float = 0.0,
    ) -> None:
        self.socket_path = socket_path
        self.chunks = chunks
        self.delay_before_send = delay_before_send
        self.inter_chunk_delay = inter_chunk_delay
        self._socket = _MemorySocket(
            chunks,
            receive_delay=delay_before_send or inter_chunk_delay,
        )

    @property
    def request(self) -> bytes:
        return bytes(self._socket.sent)

    def client(self, **kwargs: object) -> FirecrackerApiClient:
        return _ConnectedClient(self._socket, **kwargs)

    def __enter__(self) -> "_ScriptedServer":
        return self

    def __exit__(self, *_args: object) -> None:
        pass


class FirecrackerApiClientTests(unittest.TestCase):
    def test_put_json_requires_exact_204_and_emits_canonical_request(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cindermote-fc-api-") as directory:
            path = Path(directory) / "api.socket"
            response = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
            with _ScriptedServer(path, [response]) as server:
                client = server.client()
                result = client.put_json(
                    "/machine-config",
                    {"vcpu_count": 1, "mem_size_mib": 1024},
                )

            self.assertIsNone(result)
            head, body = server.request.split(b"\r\n\r\n", 1)
            self.assertTrue(head.startswith(b"PUT /machine-config HTTP/1.1\r\n"))
            self.assertIn(b"Connection: close\r\n", head + b"\r\n")
            self.assertIn(b"Content-Type: application/json\r\n", head + b"\r\n")
            self.assertEqual(
                json.loads(body),
                {"mem_size_mib": 1024, "vcpu_count": 1},
            )
            self.assertIn(f"Content-Length: {len(body)}".encode("ascii"), head)

    def test_fragmented_get_decodes_strict_json(self) -> None:
        body = b'{"firecracker_version":"1.16.1"}'
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json; charset=utf-8\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
            + body
        )
        chunks = [response[index : index + 3] for index in range(0, len(response), 3)]
        with tempfile.TemporaryDirectory(prefix="cindermote-fc-api-") as directory:
            path = Path(directory) / "api.socket"
            with _ScriptedServer(path, chunks) as server:
                value = server.client().get_json("/version")

            self.assertEqual(value, {"firecracker_version": "1.16.1"})
            self.assertTrue(server.request.startswith(b"GET /version HTTP/1.1\r\n"))

    def test_unexpected_status_preserves_bounded_response_and_fault(self) -> None:
        body = b'{"fault_message":"machine config rejected"}'
        response = (
            b"HTTP/1.1 400 Bad Request\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
            + body
        )
        with tempfile.TemporaryDirectory(prefix="cindermote-fc-api-") as directory:
            path = Path(directory) / "api.socket"
            with _ScriptedServer(path, [response]) as server:
                with self.assertRaises(FirecrackerStatusError) as raised:
                    server.client().put_json("/machine-config", {})

        self.assertEqual(raised.exception.response.status, 400)
        self.assertEqual(raised.exception.expected_statuses, (204,))
        self.assertEqual(raised.exception.fault_message, "machine config rejected")
        self.assertIn("expected 204", str(raised.exception))

    def test_declared_oversized_body_fails_before_body_read(self) -> None:
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 17\r\n\r\n"
        )
        with tempfile.TemporaryDirectory(prefix="cindermote-fc-api-") as directory:
            path = Path(directory) / "api.socket"
            with _ScriptedServer(path, [response]) as server:
                client = server.client(max_response_body_bytes=16)
                with self.assertRaises(FirecrackerResponseTooLarge):
                    client.get_json("/version")

    def test_ambiguous_response_framing_is_rejected(self) -> None:
        responses = {
            "duplicate content length": (
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                b"Content-Length: 2\r\n\r\n{}"
            ),
            "transfer encoding": (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"2\r\n{}\r\n0\r\n\r\n"
            ),
            "bytes after content length": (
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}extra"
            ),
        }
        for name, response in responses.items():
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory(prefix="cindermote-fc-api-") as directory:
                    path = Path(directory) / "api.socket"
                    with _ScriptedServer(path, [response]) as server:
                        with self.assertRaises(FirecrackerProtocolError):
                            server.client().request(
                                "GET",
                                "/version",
                                expected_status=200,
                            )

    def test_strict_response_json_rejects_duplicates_and_nonfinite_values(self) -> None:
        bodies = [b'{"a":1,"a":2}', b'{"value":1e999}']
        for body in bodies:
            with self.subTest(body=body):
                response = (
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                    + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
                    + body
                )
                with tempfile.TemporaryDirectory(prefix="cindermote-fc-api-") as directory:
                    path = Path(directory) / "api.socket"
                    with _ScriptedServer(path, [response]) as server:
                        with self.assertRaises(FirecrackerJsonError):
                            server.client().get_json("/version")

    def test_request_json_rejects_unsafe_python_values_before_connect(self) -> None:
        path = Path(tempfile.gettempdir()) / "does-not-exist-fc-api.socket"
        client = FirecrackerApiClient(path, max_request_body_bytes=32)
        cyclic: dict[str, object] = {}
        cyclic["self"] = cyclic
        invalid_payloads = [
            {1: "non-string key"},
            {"value": float("nan")},
            {"value": (1, 2)},
            {"value": "x" * 100},
            cyclic,
        ]
        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                with self.assertRaises(FirecrackerJsonError):
                    client.put_json("/machine-config", payload)  # type: ignore[arg-type]
        with self.assertRaises(FirecrackerJsonError):
            client.request(
                "GET",
                "/version",
                expected_status=200,
                payload={"not": "allowed"},
            )

    def test_endpoint_validation_blocks_request_target_injection(self) -> None:
        path = Path(tempfile.gettempdir()) / "does-not-exist-fc-api.socket"
        client = FirecrackerApiClient(path)
        unsafe = [
            "machine-config",
            "//machine-config",
            "/drives/../actions",
            "/drives/%2e%2e",
            "/version?full=true",
            "/version#fragment",
            "/version\r\nInjected: yes",
            "/network-interfaces/eth0/",
        ]
        for endpoint in unsafe:
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(ValueError):
                    client.request("GET", endpoint, expected_status=200)

        self.assertEqual(build_endpoint("drives", "rootfs"), "/drives/rootfs")
        with self.assertRaises(ValueError):
            build_endpoint("drives", "root/fs")

    def test_single_absolute_deadline_bounds_delayed_peer(self) -> None:
        response = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
        with tempfile.TemporaryDirectory(prefix="cindermote-fc-api-") as directory:
            path = Path(directory) / "api.socket"
            with _ScriptedServer(
                path,
                [response[:12], response[12:]],
                inter_chunk_delay=0.03,
            ) as server:
                client = server.client(timeout_sec=0.05)
                started = time.monotonic()
                with self.assertRaises(FirecrackerTimeoutError):
                    client.put_json("/machine-config", {})
                elapsed = time.monotonic() - started

        self.assertLess(elapsed, 0.15)

    def test_socket_path_must_be_absolute_socket_and_not_symlink(self) -> None:
        unsafe_paths = [
            "relative/api.socket",
            "/tmp/./api.socket",
            "/tmp/../api.socket",
            "/tmp//api.socket",
            "//tmp/api.socket",
            "/tmp/api.socket\n",
        ]
        for path in unsafe_paths:
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    FirecrackerApiClient(path)

        with tempfile.TemporaryDirectory(prefix="cindermote-fc-api-") as directory:
            directory_path = Path(directory)
            regular = directory_path / "regular"
            regular.write_text("not a socket", encoding="utf-8")
            with self.assertRaises(FirecrackerTransportError):
                FirecrackerApiClient(regular).request(
                    "GET", "/version", expected_status=200
                )

            linked_socket = directory_path / "linked.socket"
            with mock.patch(
                "mote.firecracker_api.os.lstat",
                return_value=SimpleNamespace(st_mode=stat.S_IFLNK),
            ):
                with self.assertRaises(FirecrackerTransportError):
                    FirecrackerApiClient(linked_socket).request(
                        "GET", "/version", expected_status=200
                    )

    def test_short_body_and_wrong_content_type_fail_closed(self) -> None:
        responses = [
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n{}",
            (
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                b"Content-Length: 2\r\n\r\n{}"
            ),
        ]
        expected_errors = [FirecrackerProtocolError, FirecrackerJsonError]
        for response, error_type in zip(responses, expected_errors, strict=True):
            with self.subTest(error=error_type.__name__):
                with tempfile.TemporaryDirectory(prefix="cindermote-fc-api-") as directory:
                    path = Path(directory) / "api.socket"
                    with _ScriptedServer(path, [response]) as server:
                        with self.assertRaises(error_type):
                            server.client().get_json("/version")


if __name__ == "__main__":
    unittest.main()
