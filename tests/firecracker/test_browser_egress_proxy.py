#!/usr/bin/env python3
from __future__ import annotations

import socket
import sys
import threading
import time
import unittest
from pathlib import Path
from typing import Callable


PROJECT_DIR = Path(__file__).resolve().parents[2]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

import broker.browser_egress_proxy as proxy_module  # noqa: E402
from broker.browser_egress_proxy import (  # noqa: E402
    BrowserEgressConfigurationError,
    BrowserEgressProxy,
    BrowserEgressStartupError,
    ProxyLimits,
)
from mote.browser_contract import make_probe_request  # noqa: E402


PUBLIC_A = "8.8.8.8"
PUBLIC_B = "1.1.1.1"
GUEST_IP = "172.30.0.2"


def _local_socket_io_available() -> bool:
    left: socket.socket | None = None
    right: socket.socket | None = None
    try:
        left, right = socket.socketpair()
        left.sendall(b"x")
        return right.recv(1) == b"x"
    except OSError:
        return False
    finally:
        if left is not None:
            left.close()
        if right is not None:
            right.close()


LOCAL_SOCKET_IO = _local_socket_io_available()


class _MemoryUpstream:
    def __init__(
        self,
        *,
        peer: str = PUBLIC_A,
        peer_port: int = 80,
        response: bytes = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
    ) -> None:
        self.peer = peer
        self.peer_port = peer_port
        self.chunks = [response, b""]
        self.sent = bytearray()
        self.closed = False
        self.timeout: float | None = None

    def getpeername(self) -> tuple[str, int]:
        return self.peer, self.peer_port

    def settimeout(self, value: float | None) -> None:
        self.timeout = value

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)

    def recv(self, count: int) -> bytes:
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if len(chunk) > count:
            self.chunks.insert(0, chunk[count:])
            chunk = chunk[:count]
        return chunk

    def close(self) -> None:
        self.closed = True

    def shutdown(self, _how: int) -> None:
        pass

    def fileno(self) -> int:
        raise AssertionError("plain HTTP upstream should not enter tunnel relay")


class _Connector:
    def __init__(self, factory: Callable[[str, int], _MemoryUpstream] | None = None) -> None:
        self.factory = factory or (lambda address, _port: _MemoryUpstream(peer=address))
        self.calls: list[tuple[str, int, float]] = []
        self.upstreams: list[_MemoryUpstream] = []

    def __call__(self, address: str, port: int, timeout: float) -> _MemoryUpstream:
        self.calls.append((address, port, timeout))
        upstream = self.factory(address, port)
        self.upstreams.append(upstream)
        return upstream


class _MemoryClient:
    """One-request client double; no host networking is exercised by tests."""

    def __init__(self, request: bytes, *, peer_ip: str = GUEST_IP) -> None:
        self.chunks = [request, b""]
        self.peer_ip = peer_ip
        self.sent = bytearray()
        self.closed = False
        self.timeout: float | None = None

    def recv(self, count: int) -> bytes:
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if len(chunk) > count:
            self.chunks.insert(0, chunk[count:])
            chunk = chunk[:count]
        return chunk

    def getpeername(self) -> tuple[str, int]:
        return self.peer_ip, 49152

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)

    def settimeout(self, value: float | None) -> None:
        self.timeout = value

    def shutdown(self, _how: int) -> None:
        pass

    def close(self) -> None:
        self.closed = True

    def fileno(self) -> int:
        raise AssertionError("client double should not enter an authorized tunnel")


def _exchange(
    proxy: BrowserEgressProxy,
    request: bytes,
    *,
    peer_ip: str = GUEST_IP,
) -> bytes:
    client = _MemoryClient(request, peer_ip=peer_ip)
    proxy.handle_client(client)
    if not client.closed:
        raise AssertionError("proxy did not close the client")
    return bytes(client.sent)


def _proxy(
    request: dict | None = None,
    *,
    resolver: Callable[[str], list[str]] | None = None,
    connector: _Connector | None = None,
    limits: ProxyLimits | None = None,
) -> BrowserEgressProxy:
    return BrowserEgressProxy(
        request or make_probe_request("http://example.com/"),
        bind_host="127.0.0.1",
        allowed_client_ip=GUEST_IP,
        bind_port=43127,
        resolver=resolver or (lambda _host: [PUBLIC_A]),
        connector=connector or _Connector(),
        limits=limits,
    )


class _PeerSocket:
    """Selectable local socket whose asserted remote peer is the pinned origin."""

    def __init__(self, endpoint: socket.socket, address: str, port: int) -> None:
        self.endpoint = endpoint
        self.address = address
        self.port = port

    def getpeername(self) -> tuple[str, int]:
        return self.address, self.port

    def fileno(self) -> int:
        return self.endpoint.fileno()

    def settimeout(self, value: float | None) -> None:
        self.endpoint.settimeout(value)

    def recv(self, count: int) -> bytes:
        return self.endpoint.recv(count)

    def sendall(self, data: bytes) -> None:
        self.endpoint.sendall(data)

    def shutdown(self, how: int) -> None:
        self.endpoint.shutdown(how)

    def close(self) -> None:
        self.endpoint.close()


class _TunnelConnector:
    def __init__(self) -> None:
        self.peer: socket.socket | None = None

    def __call__(self, address: str, port: int, _timeout: float) -> _PeerSocket:
        proxy_side, origin_side = socket.socketpair()
        self.peer = origin_side
        return _PeerSocket(proxy_side, address, port)


def _unused_loopback_port() -> int:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])
    finally:
        listener.close()


def _listener_proxy(
    request: dict,
    *,
    allowed_client_ip: str = "127.0.0.1",
    connector: object | None = None,
    limits: ProxyLimits | None = None,
) -> BrowserEgressProxy:
    return BrowserEgressProxy(
        request,
        bind_host="127.0.0.1",
        bind_port=_unused_loopback_port(),
        allowed_client_ip=allowed_client_ip,
        resolver=lambda _host: [PUBLIC_A],
        connector=connector or _Connector(),  # type: ignore[arg-type]
        limits=limits,
    )


class BrowserEgressStartupTests(unittest.TestCase):
    def test_pre_handler_rejection_can_never_claim_complete_telemetry(self) -> None:
        proxy = _proxy()
        client = _MemoryClient(b"")
        proxy._begin_runtime()
        proxy._reject_before_thread(client, 503)
        proxy.shutdown()

        telemetry = proxy.telemetry_snapshot()
        self.assertEqual(telemetry["listener_rejections"], 1)
        self.assertFalse(telemetry["complete"])

    def test_server_tracks_and_boundedly_joins_daemon_handlers(self) -> None:
        entered = threading.Event()
        release = threading.Event()
        server = object.__new__(proxy_module._ProxyServer)
        server._thread_slots = threading.BoundedSemaphore(1)
        server._handler_condition = threading.Condition()
        server._handler_threads = set()
        server.proxy = type(
            "ProxyStub",
            (),
            {
                "_transport_rejection_status": lambda _self, _address: None,
                "_reject_before_thread": lambda _self, _request, _status: None,
            },
        )()
        server.finish_request = lambda _request, _address: (
            entered.set(),
            release.wait(timeout=1.0),
        )
        server.handle_error = lambda _request, _address: None
        server.shutdown_request = lambda _request: None

        server.process_request(object(), (GUEST_IP, 12345))
        self.assertTrue(entered.wait(timeout=1.0))
        self.assertFalse(server.join_handlers(0.01))
        release.set()
        self.assertTrue(server.join_handlers(1.0))

    def test_requires_canonical_contract_and_non_wildcard_listener(self) -> None:
        noncanonical = make_probe_request("http://example.com/")
        noncanonical["url"] = "HTTP://EXAMPLE.COM/"
        with self.assertRaises(BrowserEgressConfigurationError):
            BrowserEgressProxy(
                noncanonical,
                bind_host="127.0.0.1",
                allowed_client_ip=GUEST_IP,
                resolver=lambda _host: [PUBLIC_A],
            )
        with self.assertRaises(BrowserEgressConfigurationError):
            BrowserEgressProxy(
                make_probe_request("http://example.com/"),
                bind_host=PUBLIC_A,
                allowed_client_ip=GUEST_IP,
                resolver=lambda _host: [PUBLIC_A],
            )
        with self.assertRaises(BrowserEgressConfigurationError):
            BrowserEgressProxy(
                make_probe_request("http://example.com/"),
                bind_host="0.0.0.0",
                allowed_client_ip=GUEST_IP,
                resolver=lambda _host: [PUBLIC_A],
            )

    def test_pre_resolves_every_host_and_pins_sorted_unique_answers(self) -> None:
        request = make_probe_request(
            "https://example.com/",
            authorized_origins=[
                "https://example.com",
                "http://cdn.example.com:8080",
            ],
        )
        calls: list[str] = []

        def resolver(host: str) -> list[str]:
            calls.append(host)
            return [PUBLIC_A, PUBLIC_B, PUBLIC_A]

        proxy = _proxy(request, resolver=resolver)
        self.assertEqual(calls, ["cdn.example.com", "example.com"])
        self.assertEqual(proxy.pinned_addresses["example.com"], (PUBLIC_B, PUBLIC_A))
        self.assertEqual(proxy.pinned_addresses["cdn.example.com"], (PUBLIC_B, PUBLIC_A))

    def test_any_unsafe_or_empty_dns_answer_fails_closed(self) -> None:
        for answers in ([PUBLIC_A, "127.0.0.1"], [], ["169.254.169.254"]):
            with self.subTest(answers=answers), self.assertRaises(BrowserEgressStartupError):
                _proxy(resolver=lambda _host, answers=answers: answers)


class BrowserEgressHTTPTests(unittest.TestCase):
    def test_only_the_configured_microvm_peer_can_consume_authority(self) -> None:
        connector = _Connector()
        proxy = _proxy(connector=connector)
        response = _exchange(
            proxy,
            b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
            peer_ip="172.30.0.99",
        )
        self.assertTrue(response.startswith(b"HTTP/1.1 403"))
        self.assertEqual(connector.calls, [])
        self.assertEqual(proxy.events_snapshot(), [])

    def test_get_is_sanitized_forwarded_to_pinned_ip_and_metadata_only(self) -> None:
        connector = _Connector()
        proxy = _proxy(connector=connector)
        response = _exchange(
            proxy,
            b"GET http://example.com/private/path?secret=value HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"User-Agent: Test Browser\r\n"
            b"Proxy-Authorization: should-not-pass\r\n\r\n",
        )

        # Credential-bearing proxy headers make the whole request fail closed;
        # no upstream connection occurs and no attacker text reaches metadata.
        self.assertTrue(response.startswith(b"HTTP/1.1 403"))
        self.assertEqual(connector.calls, [])
        event = proxy.events_snapshot()[0]
        self.assertEqual(event["disposition"], "blocked")
        self.assertEqual(event["reason_code"], "request_body_blocked")
        self.assertNotIn("secret", repr(event))
        self.assertNotIn("should-not-pass", repr(event))

        connector2 = _Connector()
        proxy2 = _proxy(connector=connector2)
        clean_response = _exchange(
            proxy2,
            b"GET http://example.com/private/path?secret=value HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"User-Agent: Test Browser\r\n"
            b"X-Untrusted: drop-me\r\n\r\n",
        )
        self.assertTrue(clean_response.startswith(b"HTTP/1.1 204"))
        self.assertEqual(connector2.calls[0][0:2], (PUBLIC_A, 80))
        forwarded = bytes(connector2.upstreams[0].sent)
        self.assertIn(b"GET /private/path?secret=value HTTP/1.1\r\n", forwarded)
        self.assertIn(b"Host: example.com\r\n", forwarded)
        self.assertIn(b"user-agent: Test Browser\r\n", forwarded)
        self.assertNotIn(b"X-Untrusted", forwarded)
        self.assertNotIn(b"Proxy-Authorization", forwarded)
        allowed = proxy2.events_snapshot()[0]
        self.assertEqual(allowed["web_origin"], "http://example.com")
        self.assertIsNone(allowed["connect_authority"])
        self.assertNotIn("origin", allowed)
        self.assertEqual(allowed["disposition"], "allowed")
        self.assertNotIn("private", repr(allowed))
        self.assertNotIn("secret", repr(allowed))
        adapted = proxy2.browser_events_snapshot()[0]
        self.assertEqual(adapted["web_origin"], "http://example.com")
        self.assertIsNone(adapted["connect_authority"])

    def test_post_and_unauthorized_exact_origin_never_connect(self) -> None:
        connector = _Connector()
        proxy = _proxy(connector=connector)
        post = _exchange(
            proxy,
            b"POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        other = _exchange(
            proxy,
            b"GET http://sub.example.com/ HTTP/1.1\r\nHost: sub.example.com\r\n\r\n",
        )
        mismatch = _exchange(
            proxy,
            b"HEAD http://example.com/ HTTP/1.1\r\nHost: attacker.example.com\r\n\r\n",
        )
        self.assertTrue(post.startswith(b"HTTP/1.1 405"))
        self.assertTrue(other.startswith(b"HTTP/1.1 403"))
        self.assertTrue(mismatch.startswith(b"HTTP/1.1 403"))
        self.assertEqual(connector.calls, [])
        self.assertEqual(
            [event["reason_code"] for event in proxy.events_snapshot()],
            ["method_blocked", "unauthorized_origin", "unauthorized_origin"],
        )

    def test_connected_peer_is_rechecked_against_selected_pin(self) -> None:
        connector = _Connector(
            lambda _address, _port: _MemoryUpstream(peer=PUBLIC_B)
        )
        proxy = _proxy(connector=connector)
        response = _exchange(
            proxy,
            b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        self.assertTrue(response.startswith(b"HTTP/1.1 502"))
        self.assertTrue(connector.upstreams[0].closed)
        self.assertEqual(proxy.events_snapshot()[0]["reason_code"], "peer_mismatch")

        wrong_port_connector = _Connector(
            lambda address, _port: _MemoryUpstream(peer=address, peer_port=81)
        )
        wrong_port_proxy = _proxy(connector=wrong_port_connector)
        wrong_port_response = _exchange(
            wrong_port_proxy,
            b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        self.assertTrue(wrong_port_response.startswith(b"HTTP/1.1 502"))
        self.assertEqual(
            wrong_port_proxy.events_snapshot()[0]["reason_code"], "peer_mismatch"
        )

    def test_header_and_global_byte_budgets_fail_closed(self) -> None:
        connector = _Connector(
            lambda address, _port: _MemoryUpstream(
                peer=address,
                response=b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n" + b"x" * 100,
            )
        )
        request = make_probe_request(
            "http://example.com/",
            budgets={"max_network_bytes": 80},
        )
        proxy = _proxy(request, connector=connector)
        _exchange(
            proxy,
            b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        budget_event = proxy.events_snapshot()[0]
        self.assertEqual(budget_event["reason_code"], "byte_limit")
        # The request reached the origin before the response exhausted the
        # budget, so evidence must never relabel performed egress as blocked.
        self.assertEqual(budget_event["disposition"], "allowed")
        self.assertEqual(
            proxy.browser_events_snapshot()[0]["kind"], "telemetry_loss"
        )
        self.assertLessEqual(proxy.telemetry_snapshot()["network_bytes"], 80)

        limited = _proxy(limits=ProxyLimits(max_header_bytes=1024))
        oversized = _exchange(
            limited,
            b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nX: "
            + b"a" * 1100
            + b"\r\n\r\n",
        )
        self.assertTrue(oversized.startswith(b"HTTP/1.1 431"))
        self.assertEqual(limited.events_snapshot()[0]["reason_code"], "header_limit")

    def test_event_and_connection_limits_deny_without_unbounded_records(self) -> None:
        proxy = _proxy(
            limits=ProxyLimits(max_connections=1, max_concurrent_connections=1, max_events=2)
        )
        request = b"POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"
        self.assertTrue(_exchange(proxy, request).startswith(b"HTTP/1.1 405"))
        self.assertTrue(_exchange(proxy, request).startswith(b"HTTP/1.1 503"))
        self.assertTrue(_exchange(proxy, request).startswith(b"HTTP/1.1 503"))
        self.assertEqual(len(proxy.events_snapshot()), 2)
        snapshot = proxy.telemetry_snapshot()
        self.assertTrue(snapshot["event_overflow"])
        self.assertFalse(snapshot["complete"])

    def test_global_byte_reservations_are_exact_under_concurrency(self) -> None:
        send_barrier = threading.Barrier(2)

        class _ConcurrentUpstream(_MemoryUpstream):
            def sendall(self, data: bytes) -> None:
                super().sendall(data)
                send_barrier.wait(timeout=1.0)

        connector = _Connector(
            lambda address, _port: _ConcurrentUpstream(
                peer=address,
                response=b"HTTP/1.1 200 OK\r\nContent-Length: 512\r\n\r\n"
                + b"x" * 512,
            )
        )
        request = make_probe_request(
            "http://example.com/",
            budgets={"max_network_bytes": 200},
        )
        proxy = _proxy(
            request,
            connector=connector,
            limits=ProxyLimits(
                max_connections=2,
                max_concurrent_connections=2,
            ),
        )
        wire_request = (
            b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"
        )
        workers = [
            threading.Thread(target=_exchange, args=(proxy, wire_request))
            for _ in range(2)
        ]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=2.0)
            self.assertFalse(worker.is_alive())

        snapshot = proxy.telemetry_snapshot()
        self.assertEqual(snapshot["network_bytes"], 200)
        self.assertEqual(len(proxy.events_snapshot()), 2)
        self.assertTrue(
            all(event["reason_code"] == "byte_limit" for event in proxy.events_snapshot())
        )


class BrowserEgressConnectTests(unittest.TestCase):
    def test_connect_requires_exact_authorized_https_host_and_port(self) -> None:
        request = make_probe_request("https://example.com/")
        connector = _Connector()
        proxy = _proxy(request, connector=connector)
        wrong_port = _exchange(
            proxy,
            b"CONNECT example.com:8443 HTTP/1.1\r\nHost: example.com:8443\r\n\r\n",
        )
        wrong_host = _exchange(
            proxy,
            b"CONNECT sub.example.com:443 HTTP/1.1\r\nHost: sub.example.com:443\r\n\r\n",
        )
        self.assertTrue(wrong_port.startswith(b"HTTP/1.1 403"))
        self.assertTrue(wrong_host.startswith(b"HTTP/1.1 403"))
        self.assertEqual(connector.calls, [])
        event = proxy.events_snapshot()[0]
        self.assertEqual(event["connect_authority"], "example.com:8443")
        self.assertIsNone(event["web_origin"])
        self.assertNotIn("origin", event)
        adapted = proxy.browser_events_snapshot()[0]
        self.assertEqual(adapted["connect_authority"], "example.com:8443")
        self.assertIsNone(adapted["web_origin"])

    def test_browser_event_adapter_is_bounded_and_fail_closed_for_no_origin(self) -> None:
        proxy = _proxy()
        _exchange(proxy, b"BROKEN\r\n\r\n")
        raw = proxy.events_snapshot()[0]
        self.assertIsNone(raw["web_origin"])
        self.assertIsNone(raw["connect_authority"])
        adapted = proxy.browser_events_snapshot()[0]
        self.assertEqual(adapted["kind"], "telemetry_loss")
        self.assertEqual(adapted["disposition"], "observed")


@unittest.skipUnless(LOCAL_SOCKET_IO, "sandbox forbids local socket I/O")
class BrowserEgressRealListenerTests(unittest.TestCase):
    def test_completed_connect_emits_only_transport_authority_evidence(self) -> None:
        connector = _TunnelConnector()
        proxy = _listener_proxy(
            make_probe_request("https://example.com/"),
            connector=connector,
        )
        address = proxy.start()
        client = socket.create_connection(address, timeout=1.0)
        try:
            client.sendall(
                b"CONNECT example.com:443 HTTP/1.1\r\n"
                b"Host: example.com:443\r\n\r\n"
            )
            self.assertTrue(client.recv(4096).startswith(b"HTTP/1.1 200"))
            self.assertIsNotNone(connector.peer)
            assert connector.peer is not None
            client.shutdown(socket.SHUT_WR)
            connector.peer.shutdown(socket.SHUT_WR)
            deadline = time.monotonic() + 1.0
            while (
                proxy.telemetry_snapshot()["active_connections"] != 0
                and time.monotonic() < deadline
            ):
                time.sleep(0.005)
            self.assertEqual(proxy.telemetry_snapshot()["active_connections"], 0)
            proxy.stop()

            raw = proxy.events_snapshot()[0]
            self.assertEqual(raw["reason_code"], "completed")
            self.assertEqual(raw["connect_authority"], "example.com:443")
            self.assertIsNone(raw["web_origin"])
            event = proxy.browser_events_snapshot()[0]
            self.assertEqual(event["connect_authority"], "example.com:443")
            self.assertIsNone(event["web_origin"])
            self.assertNotIn("origin", event)
        finally:
            client.close()
            if connector.peer is not None:
                connector.peer.close()
            proxy.stop()

    def test_stop_waits_until_an_accepted_handler_has_exited(self) -> None:
        proxy = _listener_proxy(make_probe_request("http://example.com/"))
        entered = threading.Event()
        release = threading.Event()
        stopped = threading.Event()
        errors: list[BaseException] = []
        original_handle = proxy.handle_client

        def delayed_handle(client: object) -> None:
            entered.set()
            release.wait(timeout=1.0)
            original_handle(client)  # type: ignore[arg-type]

        proxy.handle_client = delayed_handle  # type: ignore[method-assign]
        address = proxy.start()
        client = socket.create_connection(address, timeout=1.0)

        def stop_proxy() -> None:
            try:
                proxy.stop()
            except BaseException as exc:
                errors.append(exc)
            finally:
                stopped.set()

        stopper = threading.Thread(target=stop_proxy)
        try:
            self.assertTrue(entered.wait(timeout=1.0))
            stopper.start()
            self.assertFalse(stopped.wait(timeout=0.05))
            release.set()
            stopper.join(timeout=1.0)
            self.assertFalse(stopper.is_alive())
            self.assertEqual(errors, [])
            assert proxy._server is not None
            self.assertTrue(proxy._server.join_handlers(0.0))
        finally:
            release.set()
            client.close()
            if stopper.is_alive():
                stopper.join(timeout=1.0)
            proxy.stop()

    def test_listener_rejects_wrong_peer_before_evidence_or_upstream(self) -> None:
        connector = _Connector()
        proxy = _listener_proxy(
            make_probe_request("http://example.com/"),
            allowed_client_ip=GUEST_IP,
            connector=connector,
        )
        address = proxy.start()
        client = socket.create_connection(address, timeout=1.0)
        try:
            client.sendall(
                b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"
            )
            self.assertTrue(client.recv(4096).startswith(b"HTTP/1.1 403"))
        finally:
            client.close()
            proxy.stop()
        self.assertEqual(connector.calls, [])
        self.assertEqual(proxy.events_snapshot(), [])
        self.assertEqual(proxy.telemetry_snapshot()["listener_rejections"], 1)
        self.assertFalse(proxy.telemetry_snapshot()["complete"])

    def test_concurrency_is_rejected_before_a_second_worker_is_created(self) -> None:
        proxy = _listener_proxy(
            make_probe_request("http://example.com/"),
            limits=ProxyLimits(
                max_connections=4,
                max_concurrent_connections=1,
            ),
        )
        address = proxy.start()
        first = socket.create_connection(address, timeout=1.0)
        second: socket.socket | None = None
        try:
            deadline = time.monotonic() + 1.0
            while (
                proxy.telemetry_snapshot()["active_connections"] != 1
                and time.monotonic() < deadline
            ):
                time.sleep(0.005)
            self.assertEqual(proxy.telemetry_snapshot()["active_connections"], 1)

            second = socket.create_connection(address, timeout=1.0)
            second.sendall(
                b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"
            )
            self.assertTrue(second.recv(4096).startswith(b"HTTP/1.1 503"))
            self.assertEqual(proxy.telemetry_snapshot()["active_connections"], 1)
            self.assertEqual(proxy.telemetry_snapshot()["listener_rejections"], 1)
        finally:
            if second is not None:
                second.close()
            first.close()
            proxy.stop()
        self.assertFalse(proxy.telemetry_snapshot()["complete"])

    def test_stop_revokes_an_active_connect_tunnel(self) -> None:
        connector = _TunnelConnector()
        proxy = _listener_proxy(
            make_probe_request("https://example.com/"),
            connector=connector,
        )
        address = proxy.start()
        client = socket.create_connection(address, timeout=1.0)
        try:
            client.sendall(
                b"CONNECT example.com:443 HTTP/1.1\r\n"
                b"Host: example.com:443\r\n\r\n"
            )
            self.assertTrue(client.recv(4096).startswith(b"HTTP/1.1 200"))
            self.assertIsNotNone(connector.peer)
            assert connector.peer is not None
            connector.peer.settimeout(1.0)
            client.sendall(b"before-stop")
            self.assertEqual(connector.peer.recv(64), b"before-stop")

            proxy.stop()
            client.settimeout(1.0)
            try:
                after_stop = client.recv(1)
            except (ConnectionError, OSError):
                after_stop = b""
            self.assertEqual(after_stop, b"")
            self.assertTrue(proxy.telemetry_snapshot()["complete"])
            event = proxy.events_snapshot()[0]
            self.assertEqual(event["disposition"], "allowed")
            self.assertEqual(event["reason_code"], "proxy_closed")
        finally:
            client.close()
            if connector.peer is not None:
                connector.peer.close()
            proxy.stop()


if __name__ == "__main__":
    unittest.main()
