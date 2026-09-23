#!/usr/bin/env python3
"""Fail-closed explicit proxy for a single browser-probe contract.

The proxy is deliberately not a general-purpose forward proxy.  It accepts one
already-canonical ``cindermote.browser-probe/v1`` request, resolves and validates
every authorized DNS name before listening, and connects only to those pinned
IP addresses.  Plain HTTP is limited to ``GET`` and ``HEAD`` and yields
host-observed HTTP-origin evidence.  HTTPS is carried as an opaque ``CONNECT``
tunnel and yields only host/port transport-authority evidence; no TLS is
terminated on the host and no HTTPS web origin is claimed by this process.

This process is only one half of the network boundary.  The microVM network
namespace must have no route except to this proxy.  Otherwise Chromium could
bypass these controls with direct TCP, UDP/QUIC, or its own DNS client.

Only bounded metadata is retained.  Request paths, queries, headers, TLS data,
and response bodies are never placed in events or exception messages.
"""

from __future__ import annotations

import copy
import ipaddress
import queue
import selectors
import socket
import socketserver
import threading
import time
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping, Protocol
from urllib.parse import urlsplit

from mote.browser_contract import (
    BrowserContractError,
    normalize_origin,
    normalize_url,
    validate_probe_request,
    validate_resolved_address,
)


_MAX_DNS_ANSWERS = 16
_MAX_CONFIGURED_CONNECTIONS = 4096
_MAX_CONFIGURED_CONCURRENCY = 128
_MAX_CONFIGURED_HEADER_BYTES = 256 * 1024
_MAX_CONFIGURED_HEADER_COUNT = 512
_MAX_CONFIGURED_EVENT_COUNT = 100_000
_MAX_REQUEST_LINE_BYTES = 8192
_IO_CHUNK_BYTES = 64 * 1024
_HANDLER_SHUTDOWN_TIMEOUT_SEC = 2.0
_SHUTDOWN_COORDINATION_TIMEOUT_SEC = 3.0
_TUNNEL_POLL_INTERVAL_SEC = 0.1
_RESOLVER_SLOTS = threading.BoundedSemaphore(4)

_HEADER_NAME_BYTES = frozenset(
    b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)
_FORWARDED_REQUEST_HEADERS = frozenset(
    {
        "accept",
        "accept-encoding",
        "accept-language",
        "cache-control",
        "cookie",
        "dnt",
        "if-modified-since",
        "if-none-match",
        "pragma",
        "range",
        "referer",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "sec-fetch-user",
        "upgrade-insecure-requests",
        "user-agent",
    }
)
_REJECTED_REQUEST_HEADERS = frozenset(
    {
        "authorization",
        "content-length",
        "expect",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)

_REASON_CODES = frozenset(
    {
        "completed",
        "client_closed",
        "malformed_request",
        "header_limit",
        "method_blocked",
        "unauthorized_origin",
        "unauthorized_client",
        "request_body_blocked",
        "connection_limit",
        "concurrency_limit",
        "event_limit",
        "byte_limit",
        "deadline",
        "upstream_failure",
        "peer_mismatch",
        "proxy_closed",
    }
)


class BrowserEgressError(RuntimeError):
    """Base class for browser egress startup and runtime failures."""


class BrowserEgressConfigurationError(BrowserEgressError, ValueError):
    """The proxy configuration is unsafe or internally inconsistent."""


class BrowserEgressStartupError(BrowserEgressError):
    """The allowlist could not be resolved and pinned safely."""


class BrowserEgressClosed(BrowserEgressError):
    """The proxy was used after its authority was revoked."""


class _ProxyRejection(Exception):
    """Internal, fixed-reason rejection that is safe to reduce to metadata."""

    def __init__(
        self,
        status: int,
        reason_code: str,
        *,
        web_origin: str | None = None,
        connect_authority: str | None = None,
        response_started: bool = False,
        egress_performed: bool = False,
    ) -> None:
        if reason_code not in _REASON_CODES:
            raise AssertionError("unknown fixed proxy reason code")
        self.status = status
        self.reason_code = reason_code
        self.web_origin = web_origin
        self.connect_authority = connect_authority
        self.response_started = response_started
        self.egress_performed = egress_performed
        super().__init__(reason_code)


class _SocketLike(Protocol):
    def close(self) -> None: ...

    def fileno(self) -> int: ...

    def getpeername(self) -> tuple[Any, ...]: ...

    def recv(self, size: int) -> bytes: ...

    def sendall(self, data: bytes) -> None: ...

    def settimeout(self, value: float | None) -> None: ...

    def shutdown(self, how: int) -> None: ...


Resolver = Callable[[str], Iterable[str]]
Connector = Callable[[str, int, float], _SocketLike]
Clock = Callable[[], float]


@dataclass(frozen=True)
class ProxyLimits:
    """Hard-bounded local limits in addition to the probe's own budgets."""

    max_connections: int = 64
    max_concurrent_connections: int = 8
    max_header_bytes: int = 32 * 1024
    max_header_count: int = 100
    max_events: int = 1024
    resolve_timeout_sec: float = 5.0
    connect_timeout_sec: float = 5.0
    idle_timeout_sec: float = 5.0

    def __post_init__(self) -> None:
        integer_bounds = (
            ("max_connections", self.max_connections, 1, _MAX_CONFIGURED_CONNECTIONS),
            (
                "max_concurrent_connections",
                self.max_concurrent_connections,
                1,
                _MAX_CONFIGURED_CONCURRENCY,
            ),
            ("max_header_bytes", self.max_header_bytes, 1024, _MAX_CONFIGURED_HEADER_BYTES),
            ("max_header_count", self.max_header_count, 1, _MAX_CONFIGURED_HEADER_COUNT),
            ("max_events", self.max_events, 1, _MAX_CONFIGURED_EVENT_COUNT),
        )
        for name, value, minimum, maximum in integer_bounds:
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not minimum <= value <= maximum
            ):
                raise BrowserEgressConfigurationError(
                    f"{name} must be an integer in {minimum}..{maximum}"
                )
        if self.max_concurrent_connections > self.max_connections:
            raise BrowserEgressConfigurationError(
                "max_concurrent_connections cannot exceed max_connections"
            )
        for name, value in (
            ("resolve_timeout_sec", self.resolve_timeout_sec),
            ("connect_timeout_sec", self.connect_timeout_sec),
            ("idle_timeout_sec", self.idle_timeout_sec),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not 0.01 <= float(value) <= 60.0
            ):
                raise BrowserEgressConfigurationError(
                    f"{name} must be numeric in 0.01..60.0"
                )


@dataclass(frozen=True)
class _OriginPolicy:
    origin: str
    scheme: str
    hostname: str
    port: int
    addresses: tuple[str, ...]


@dataclass
class _TransferCounts:
    client_to_origin: int = 0
    origin_to_client: int = 0


class _ByteBudget:
    def __init__(self, maximum: int) -> None:
        self.maximum = maximum
        self._used = 0
        self._reserved = 0
        self._lock = threading.Lock()

    @property
    def used(self) -> int:
        with self._lock:
            return self._used

    @property
    def remaining(self) -> int:
        with self._lock:
            return self.maximum - self._used - self._reserved

    def consume(self, count: int) -> None:
        if count < 0:
            raise AssertionError("negative byte consumption")
        with self._lock:
            if self._used + self._reserved + count > self.maximum:
                raise _ProxyRejection(503, "byte_limit")
            self._used += count

    def reserve(self, maximum: int) -> int:
        """Reserve a bounded read before bytes cross a socket boundary."""

        if maximum <= 0:
            raise AssertionError("byte reservation must be positive")
        with self._lock:
            available = self.maximum - self._used - self._reserved
            if available <= 0:
                raise _ProxyRejection(503, "byte_limit")
            reservation = min(maximum, available)
            self._reserved += reservation
            return reservation

    def commit_reservation(self, reservation: int, actual: int) -> None:
        if not 0 <= actual <= reservation:
            raise AssertionError("invalid byte reservation commit")
        with self._lock:
            if reservation > self._reserved:
                raise AssertionError("byte reservation is not active")
            self._reserved -= reservation
            self._used += actual

    def cancel_reservation(self, reservation: int) -> None:
        with self._lock:
            if reservation > self._reserved:
                raise AssertionError("byte reservation is not active")
            self._reserved -= reservation


def _default_resolver(hostname: str) -> Iterable[str]:
    answers = socket.getaddrinfo(
        hostname,
        None,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    )
    return [answer[4][0] for answer in answers]


def _default_connector(address: str, port: int, timeout: float) -> _SocketLike:
    # ``address`` is an already-validated IP literal.  create_connection does
    # not perform DNS when passed that literal.
    return socket.create_connection((address, port), timeout=timeout)


def _canonical_bind_address(value: str) -> tuple[str, int]:
    if not isinstance(value, str) or not value or value != value.strip() or "%" in value:
        raise BrowserEgressConfigurationError("bind_host must be a plain IP literal")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise BrowserEgressConfigurationError("bind_host must be a plain IP literal") from exc
    if address.is_unspecified or address.is_multicast:
        raise BrowserEgressConfigurationError(
            "wildcard and multicast bind hosts are forbidden"
        )
    if address.is_global:
        raise BrowserEgressConfigurationError(
            "browser egress proxy cannot bind a globally routable address"
        )
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    return address.compressed, family


def _canonical_client_address(value: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or "%" in value:
        raise BrowserEgressConfigurationError(
            "allowed_client_ip must be a plain IP literal"
        )
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise BrowserEgressConfigurationError(
            "allowed_client_ip must be a plain IP literal"
        ) from exc
    if (
        address.is_unspecified
        or address.is_multicast
        or address.is_link_local
        or address.is_global
    ):
        raise BrowserEgressConfigurationError(
            "allowed_client_ip must identify the private microVM endpoint"
        )
    return address.compressed


def _origin_policy(origin: str, addresses: tuple[str, ...]) -> _OriginPolicy:
    parsed = urlsplit(origin)
    assert parsed.hostname is not None
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return _OriginPolicy(
        origin=origin,
        scheme=parsed.scheme,
        hostname=parsed.hostname,
        port=port,
        addresses=addresses,
    )


class _ProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    # ThreadingMixIn only tracks non-daemon threads.  The worker process must
    # remain killable if a handler wedges, so use daemon threads but maintain a
    # separate, complete registry with a bounded join below.
    daemon_threads = True
    block_on_close = False

    def __init__(
        self,
        address: tuple[str, int],
        handler: type[socketserver.BaseRequestHandler],
        proxy: "BrowserEgressProxy",
        *,
        family: int,
    ) -> None:
        self.address_family = family
        self.proxy = proxy
        self._thread_slots = threading.BoundedSemaphore(
            proxy._limits.max_concurrent_connections
        )
        self._handler_condition = threading.Condition()
        self._handler_threads: set[threading.Thread] = set()
        super().__init__(address, handler, bind_and_activate=False)

    def process_request(
        self,
        request: _SocketLike,
        client_address: tuple[Any, ...],
    ) -> None:
        status = self.proxy._transport_rejection_status(client_address)
        if status is not None or not self._thread_slots.acquire(blocking=False):
            self.proxy._reject_before_thread(request, status or 503)
            self.shutdown_request(request)
            return
        thread = threading.Thread(
            target=self.process_request_thread,
            args=(request, client_address),
            name="cindermote-egress-handler",
            daemon=True,
        )
        try:
            # Register and start under the same lock so shutdown cannot reap a
            # not-yet-started thread and then miss it after it becomes live.
            with self._handler_condition:
                self._handler_threads = {
                    active for active in self._handler_threads if active.is_alive()
                }
                self._handler_threads.add(thread)
                thread.start()
        except BaseException:
            with self._handler_condition:
                self._handler_threads.discard(thread)
                self._handler_condition.notify_all()
            self._thread_slots.release()
            self.shutdown_request(request)
            raise

    def process_request_thread(
        self,
        request: _SocketLike,
        client_address: tuple[Any, ...],
    ) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._thread_slots.release()
            with self._handler_condition:
                self._handler_condition.notify_all()

    def join_handlers(self, timeout: float) -> bool:
        """Wait boundedly until every accepted request handler has exited."""

        deadline = time.monotonic() + timeout
        while True:
            with self._handler_condition:
                self._handler_threads = {
                    thread for thread in self._handler_threads if thread.is_alive()
                }
                threads = list(self._handler_threads)
            if not threads:
                return True
            for thread in threads:
                if thread is threading.current_thread():
                    return False
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                thread.join(timeout=remaining)
            with self._handler_condition:
                self._handler_threads = {
                    thread for thread in self._handler_threads if thread.is_alive()
                }


class _ProxyHandler(socketserver.BaseRequestHandler):
    server: _ProxyServer

    def handle(self) -> None:
        self.server.proxy.handle_client(self.request)


class BrowserEgressProxy:
    """One-job, deny-by-default HTTP/HTTPS egress broker.

    Construction validates that ``request`` is already canonical and performs
    all DNS resolution.  A private, reserved, link-local, multicast, loopback,
    or otherwise non-global answer makes construction fail; the unsafe answer
    is not merely discarded.  Connections use only the resulting pinned IPs.
    """

    def __init__(
        self,
        request: Mapping[str, Any],
        *,
        bind_host: str,
        allowed_client_ip: str,
        bind_port: int = 3128,
        resolver: Resolver | None = None,
        connector: Connector | None = None,
        limits: ProxyLimits | None = None,
        clock: Clock = time.monotonic,
    ) -> None:
        try:
            canonical = validate_probe_request(dict(request))
        except (BrowserContractError, TypeError, ValueError) as exc:
            raise BrowserEgressConfigurationError(
                "browser probe request is not valid"
            ) from exc
        if canonical != request:
            raise BrowserEgressConfigurationError(
                "browser probe request must be canonical before proxy construction"
            )
        self._request = copy.deepcopy(canonical)

        self._bind_host, self._address_family = _canonical_bind_address(bind_host)
        self._allowed_client_ip = _canonical_client_address(allowed_client_ip)
        if (
            not isinstance(bind_port, int)
            or isinstance(bind_port, bool)
            or not 1 <= bind_port <= 65535
        ):
            raise BrowserEgressConfigurationError("bind_port must be in 1..65535")
        self._bind_port = bind_port
        self._limits = limits or ProxyLimits()
        self._resolver = resolver or _default_resolver
        self._connector = connector or _default_connector
        self._clock = clock

        self._state_lock = threading.Lock()
        self._events: dict[int, dict[str, Any]] = {}
        self._inflight_events: set[int] = set()
        self._event_overflow = False
        self._next_sequence = 0
        self._connection_attempts = 0
        self._listener_rejections = 0
        self._concurrency = threading.BoundedSemaphore(
            self._limits.max_concurrent_connections
        )
        self._started_at: float | None = None
        self._deadline: float | None = None
        self._closed = False
        self._serving = False
        self._server: _ProxyServer | None = None
        self._deadline_timer: threading.Timer | None = None
        self._active_clients: dict[int, _SocketLike] = {}
        self._active_upstreams: dict[int, _SocketLike] = {}
        self._serve_thread: threading.Thread | None = None
        self._shutdown_complete = threading.Event()
        self._shutdown_error: BrowserEgressClosed | None = None
        self._byte_budget = _ByteBudget(canonical["budgets"]["max_network_bytes"])
        self._event_limit = min(
            self._limits.max_events,
            canonical["budgets"]["max_events"],
        )

        pinned_by_host = self._pre_resolve(canonical["authorized_origins"])
        policies = {
            origin: _origin_policy(
                origin,
                pinned_by_host[urlsplit(origin).hostname or ""],
            )
            for origin in canonical["authorized_origins"]
        }
        self._policies = MappingProxyType(policies)
        self._pinned_by_host = MappingProxyType(pinned_by_host)

    @property
    def request(self) -> dict[str, Any]:
        return copy.deepcopy(self._request)

    @property
    def bind_address(self) -> tuple[str, int]:
        return self._bind_host, self._bind_port

    @property
    def allowed_client_ip(self) -> str:
        return self._allowed_client_ip

    @property
    def pinned_addresses(self) -> Mapping[str, tuple[str, ...]]:
        return self._pinned_by_host

    def _pre_resolve(self, origins: Iterable[str]) -> dict[str, tuple[str, ...]]:
        hostnames = sorted({urlsplit(origin).hostname or "" for origin in origins})
        pinned: dict[str, tuple[str, ...]] = {}
        resolve_deadline = self._clock() + float(self._limits.resolve_timeout_sec)
        for hostname in hostnames:
            result_queue: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

            if not _RESOLVER_SLOTS.acquire(blocking=False):
                raise BrowserEgressStartupError(
                    "authorized DNS resolver capacity is exhausted"
                )

            def resolve_one(name: str = hostname) -> None:
                try:
                    try:
                        answers = list(self._resolver(name))
                    except BaseException as exc:  # fixed failure at the outer boundary
                        result_queue.put((False, exc))
                    else:
                        result_queue.put((True, answers))
                finally:
                    _RESOLVER_SLOTS.release()

            worker = threading.Thread(
                target=resolve_one,
                name="cindermote-egress-dns",
                daemon=True,
            )
            try:
                worker.start()
            except BaseException as exc:
                _RESOLVER_SLOTS.release()
                raise BrowserEgressStartupError(
                    "authorized DNS resolver could not start"
                ) from exc
            remaining = resolve_deadline - self._clock()
            if remaining <= 0:
                raise BrowserEgressStartupError("authorized DNS resolution timed out")
            try:
                succeeded, value = result_queue.get(timeout=remaining)
            except queue.Empty as exc:
                raise BrowserEgressStartupError("authorized DNS resolution timed out") from exc
            if not succeeded:
                raise BrowserEgressStartupError(
                    "authorized DNS resolution failed"
                ) from None
            if not isinstance(value, list) or not 1 <= len(value) <= _MAX_DNS_ANSWERS:
                raise BrowserEgressStartupError(
                    "authorized DNS resolution returned an invalid answer count"
                )
            checked: list[str] = []
            for answer in value:
                try:
                    validated = validate_resolved_address(answer)
                except (BrowserContractError, TypeError, ValueError) as exc:
                    # A mixed public/private response fails as a whole.  Silently
                    # discarding the unsafe address enables rebinding ambiguity.
                    raise BrowserEgressStartupError(
                        "authorized DNS resolution returned an unsafe answer"
                    ) from exc
                if validated not in checked:
                    checked.append(validated)
            if not checked:
                raise BrowserEgressStartupError("authorized DNS resolution was empty")
            checked.sort(key=lambda item: (ipaddress.ip_address(item).version, int(ipaddress.ip_address(item))))
            pinned[hostname] = tuple(checked)
        return pinned

    def _begin_runtime(self) -> None:
        with self._state_lock:
            if self._closed:
                raise BrowserEgressClosed("browser egress proxy is closed")
            if self._started_at is None:
                self._started_at = self._clock()
                self._deadline = (
                    self._started_at + self._request["budgets"]["wall_clock_sec"]
                )

    def _remaining_time(self) -> float:
        with self._state_lock:
            if self._closed:
                raise _ProxyRejection(503, "proxy_closed")
            deadline = self._deadline
        if deadline is None:
            raise AssertionError("proxy runtime has not begun")
        remaining = deadline - self._clock()
        if remaining <= 0:
            raise _ProxyRejection(504, "deadline")
        return remaining

    def _peer_matches_allowed_client(self, peer: Any) -> bool:
        if not isinstance(peer, tuple) or not peer or not isinstance(peer[0], str):
            return False
        try:
            address = ipaddress.ip_address(peer[0])
        except ValueError:
            return False
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        return address.compressed == self._allowed_client_ip

    def _transport_rejection_status(self, peer: Any) -> int | None:
        """Reject unauthenticated or exhausted accepts before spawning a thread."""

        if not self._peer_matches_allowed_client(peer):
            return 403
        with self._state_lock:
            if self._closed:
                return 503
            if self._deadline is not None and self._clock() >= self._deadline:
                return 504
            if (
                self._connection_attempts >= self._limits.max_connections
                or self._next_sequence >= self._event_limit
            ):
                if self._next_sequence >= self._event_limit:
                    self._event_overflow = True
                return 503
        return None

    def _reject_before_thread(self, client: _SocketLike, status: int) -> None:
        with self._state_lock:
            # Saturate diagnostic state rather than allowing attacker-driven
            # unbounded integers or event lists.
            self._listener_rejections = min(
                self._listener_rejections + 1,
                self._limits.max_connections + self._event_limit + 1,
            )
        self._safe_error(client, status)

    def _reserve_event(self) -> int | None:
        with self._state_lock:
            if self._next_sequence >= self._event_limit:
                self._event_overflow = True
                return None
            sequence = self._next_sequence
            self._next_sequence += 1
            self._inflight_events.add(sequence)
            return sequence

    def _finish_event(
        self,
        sequence: int,
        *,
        web_origin: str | None,
        connect_authority: str | None,
        disposition: str,
        reason_code: str,
        counts: _TransferCounts,
    ) -> None:
        if disposition not in {"allowed", "blocked"}:
            raise AssertionError("invalid event disposition")
        if reason_code not in _REASON_CODES:
            raise AssertionError("invalid event reason")
        event = {
            "sequence": sequence,
            "source": "egress",
            "kind": "network_request",
            "web_origin": web_origin,
            "connect_authority": connect_authority,
            "disposition": disposition,
            "reason_code": reason_code,
            "client_to_origin_bytes": counts.client_to_origin,
            "origin_to_client_bytes": counts.origin_to_client,
        }
        with self._state_lock:
            if sequence not in self._inflight_events:
                raise AssertionError("event reservation is not active")
            self._inflight_events.remove(sequence)
            self._events[sequence] = event

    def events_snapshot(self) -> list[dict[str, Any]]:
        """Return bounded metadata only, in stable sequence order."""

        with self._state_lock:
            return [copy.deepcopy(self._events[key]) for key in sorted(self._events)]

    def browser_events_snapshot(self) -> list[dict[str, Any]]:
        """Return events shaped for ``cindermote.browser-evidence/v2``.

        A malformed request has no canonical typed destination to report.
        Such an event becomes an egress telemetry-loss marker so downstream
        reduction stays fail-closed instead of inventing a witness.
        """

        events: list[dict[str, Any]] = []
        for event in self.events_snapshot():
            # If egress occurred but completion evidence did not, preserve the
            # honest raw "allowed" disposition and make the canonical stream
            # explicitly incomplete.  Never relabel performed egress blocked.
            incomplete_allowed = (
                event["disposition"] == "allowed"
                and event["reason_code"] != "completed"
            )
            if (
                (event["web_origin"] is None)
                == (event["connect_authority"] is None)
                or incomplete_allowed
            ):
                events.append(
                    {
                        "sequence": event["sequence"],
                        "source": "egress",
                        "kind": "telemetry_loss",
                        "web_origin": None,
                        "connect_authority": None,
                        "disposition": "observed",
                    }
                )
            else:
                events.append(
                    {
                        "sequence": event["sequence"],
                        "source": "egress",
                        "kind": "network_request",
                        "web_origin": event["web_origin"],
                        "connect_authority": event["connect_authority"],
                        "disposition": event["disposition"],
                    }
                )
        return events

    def telemetry_snapshot(self) -> dict[str, Any]:
        with self._state_lock:
            started = self._started_at is not None
            closed = self._closed
            active_connections = len(self._active_clients)
            complete = (
                started
                and closed
                and not self._event_overflow
                and not self._inflight_events
                and active_connections == 0
                and not self._active_upstreams
                and self._listener_rejections == 0
            )
            attempts = self._connection_attempts
            event_overflow = self._event_overflow
            inflight = len(self._inflight_events)
            listener_rejections = self._listener_rejections
        return {
            "complete": complete,
            "started": started,
            "closed": closed,
            "event_overflow": event_overflow,
            "inflight_events": inflight,
            "active_connections": active_connections,
            "listener_rejections": listener_rejections,
            "connection_attempts": attempts,
            "event_count": len(self.events_snapshot()),
            "network_bytes": self._byte_budget.used,
            "network_byte_limit": self._byte_budget.maximum,
        }

    def bind(self) -> tuple[str, int]:
        """Bind exactly the configured IP and port, but do not serve yet."""

        self._begin_runtime()
        with self._state_lock:
            if self._server is not None:
                return self.bind_address
        server = _ProxyServer(
            self.bind_address,
            _ProxyHandler,
            self,
            family=self._address_family,
        )
        try:
            server.server_bind()
            actual = server.server_address
            actual_host = ipaddress.ip_address(actual[0]).compressed
            if actual_host != self._bind_host or actual[1] != self._bind_port:
                raise BrowserEgressStartupError(
                    "proxy listener did not bind the configured address"
                )
            server.server_activate()
        except BaseException:
            server.server_close()
            raise
        with self._state_lock:
            if self._closed or self._server is not None:
                server.server_close()
                if self._closed:
                    raise BrowserEgressClosed("browser egress proxy is closed")
                raise BrowserEgressStartupError("proxy listener was initialized twice")
            self._server = server
            assert self._deadline is not None
            timer = threading.Timer(
                max(0.0, self._deadline - self._clock()),
                self.shutdown,
            )
            timer.name = "cindermote-egress-deadline"
            timer.daemon = True
            self._deadline_timer = timer
        timer.start()
        return self.bind_address

    def serve_forever(self, poll_interval: float = 0.2) -> None:
        self.bind()
        with self._state_lock:
            if self._closed:
                raise BrowserEgressClosed("browser egress proxy is closed")
            assert self._server is not None
            self._serving = True
            server = self._server
        try:
            server.serve_forever(poll_interval=poll_interval)
        finally:
            with self._state_lock:
                self._serving = False

    def start(self) -> tuple[str, int]:
        """Bind and supervise the proxy in one daemon thread."""

        address = self.bind()
        with self._state_lock:
            if self._serve_thread is not None:
                raise BrowserEgressStartupError("proxy supervisor was initialized twice")
            thread = threading.Thread(
                target=self._serve_background,
                name="cindermote-browser-egress",
                daemon=True,
            )
            self._serve_thread = thread
        thread.start()
        return address

    def _serve_background(self) -> None:
        try:
            self.serve_forever()
        except BrowserEgressClosed:
            # ``stop`` may win the race immediately after ``start`` binds.
            pass

    def stop(self) -> None:
        """Revoke egress and boundedly join every proxy-owned thread."""

        self.shutdown()
        thread = self._serve_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=_HANDLER_SHUTDOWN_TIMEOUT_SEC)
            if thread.is_alive():
                raise BrowserEgressClosed("proxy supervisor teardown did not complete")

    def shutdown(self) -> None:
        with self._state_lock:
            if self._closed:
                owner = False
            else:
                owner = True
                self._closed = True
                server = self._server
                serving = self._serving
                timer = self._deadline_timer
                active_clients = list(self._active_clients.values())
                active_upstreams = list(self._active_upstreams.values())
        if not owner:
            if not self._shutdown_complete.wait(_SHUTDOWN_COORDINATION_TIMEOUT_SEC):
                raise BrowserEgressClosed("proxy shutdown coordination timed out")
            with self._state_lock:
                error = self._shutdown_error
            if error is not None:
                raise BrowserEgressClosed(str(error))
            return

        error: BrowserEgressClosed | None = None
        try:
            if timer is not None and timer is not threading.current_thread():
                timer.cancel()
            for client in active_clients:
                try:
                    client.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    client.close()
                except OSError:
                    pass
            for upstream in active_upstreams:
                try:
                    upstream.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    upstream.close()
                except OSError:
                    pass
            if server is not None and serving:
                server.shutdown()
            if server is not None:
                server.server_close()
                if not server.join_handlers(_HANDLER_SHUTDOWN_TIMEOUT_SEC):
                    error = BrowserEgressClosed(
                        "proxy handler teardown did not complete"
                    )
        finally:
            with self._state_lock:
                self._shutdown_error = error
            self._shutdown_complete.set()
        if error is not None:
            raise error

    def _set_timeout(self, endpoint: _SocketLike, maximum: float) -> None:
        endpoint.settimeout(min(float(maximum), self._remaining_time()))

    def _safe_error(self, client: _SocketLike, status: int) -> None:
        reason = {
            400: "Bad Request",
            403: "Forbidden",
            405: "Method Not Allowed",
            431: "Request Header Fields Too Large",
            502: "Bad Gateway",
            503: "Service Unavailable",
            504: "Gateway Timeout",
        }.get(status, "Forbidden")
        response = (
            f"HTTP/1.1 {status} {reason}\r\n"
            "Content-Length: 0\r\n"
            "Cache-Control: no-store\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        try:
            client.settimeout(0.25)
            client.sendall(response)
        except (OSError, socket.timeout):
            pass

    def handle_client(self, client: _SocketLike) -> None:
        """Handle one accepted client socket and always close it.

        This method is public to support a supervisor-owned listener and tests;
        callers must not reuse ``client`` after it returns.
        """

        counts = _TransferCounts()
        sequence: int | None = None
        web_origin: str | None = None
        connect_authority: str | None = None
        disposition = "blocked"
        reason_code = "malformed_request"
        response_started = False
        acquired = False
        registered = False
        try:
            try:
                peer = client.getpeername()
            except Exception as exc:
                raise _ProxyRejection(403, "unauthorized_client") from exc
            if not self._peer_matches_allowed_client(peer):
                raise _ProxyRejection(403, "unauthorized_client")
            try:
                self._begin_runtime()
            except BrowserEgressClosed:
                raise _ProxyRejection(503, "proxy_closed")
            with self._state_lock:
                if self._closed:
                    raise _ProxyRejection(503, "proxy_closed")
                self._active_clients[id(client)] = client
                registered = True
            sequence = self._reserve_event()
            if sequence is None:
                self._safe_error(client, 503)
                return
            with self._state_lock:
                self._connection_attempts += 1
                attempt = self._connection_attempts
            if attempt > self._limits.max_connections:
                raise _ProxyRejection(503, "connection_limit")
            acquired = self._concurrency.acquire(blocking=False)
            if not acquired:
                raise _ProxyRejection(503, "concurrency_limit")
            self._remaining_time()
            web_origin, connect_authority = self._handle_request(client, counts)
            disposition = "allowed"
            reason_code = "completed"
        except _ProxyRejection as exc:
            web_origin = exc.web_origin or web_origin
            connect_authority = exc.connect_authority or connect_authority
            reason_code = exc.reason_code
            response_started = exc.response_started
            if exc.egress_performed:
                disposition = "allowed"
            if not response_started:
                self._safe_error(client, exc.status)
        except (OSError, socket.timeout):
            reason_code = "upstream_failure"
            if not response_started:
                self._safe_error(client, 502)
        except Exception:
            # Unexpected connector/socket implementations still revoke egress;
            # no exception text or request material crosses the boundary.
            reason_code = "upstream_failure"
            if not response_started:
                self._safe_error(client, 502)
        finally:
            if registered:
                with self._state_lock:
                    self._active_clients.pop(id(client), None)
            if acquired:
                self._concurrency.release()
            if sequence is not None:
                self._finish_event(
                    sequence,
                    web_origin=web_origin,
                    connect_authority=connect_authority,
                    disposition=disposition,
                    reason_code=reason_code,
                    counts=counts,
                )
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                client.close()
            except OSError:
                pass

    def _read_request_head(self, client: _SocketLike) -> tuple[bytes, bytes]:
        data = bytearray()
        while b"\r\n\r\n" not in data:
            if len(data) >= self._limits.max_header_bytes:
                raise _ProxyRejection(431, "header_limit")
            self._set_timeout(client, self._limits.idle_timeout_sec)
            chunk = client.recv(
                min(_IO_CHUNK_BYTES, self._limits.max_header_bytes - len(data) + 1)
            )
            if not chunk:
                raise _ProxyRejection(400, "client_closed")
            data.extend(chunk)
            if len(data) > self._limits.max_header_bytes:
                raise _ProxyRejection(431, "header_limit")
        head, remainder = bytes(data).split(b"\r\n\r\n", 1)
        return head, remainder

    def _parse_request(
        self, head: bytes
    ) -> tuple[str, str, dict[str, bytes]]:
        lines = head.split(b"\r\n")
        if not lines or len(lines[0]) > _MAX_REQUEST_LINE_BYTES:
            raise _ProxyRejection(400, "malformed_request")
        if len(lines) - 1 > self._limits.max_header_count:
            raise _ProxyRejection(431, "header_limit")
        parts = lines[0].split(b" ")
        if len(parts) != 3 or any(not part for part in parts):
            raise _ProxyRejection(400, "malformed_request")
        try:
            method = parts[0].decode("ascii")
            target = parts[1].decode("ascii")
            version = parts[2].decode("ascii")
        except UnicodeDecodeError as exc:
            raise _ProxyRejection(400, "malformed_request") from exc
        if version != "HTTP/1.1":
            raise _ProxyRejection(400, "malformed_request")

        headers: dict[str, bytes] = {}
        for line in lines[1:]:
            if not line or line[:1] in {b" ", b"\t"} or b":" not in line:
                raise _ProxyRejection(400, "malformed_request")
            raw_name, raw_value = line.split(b":", 1)
            if (
                not raw_name
                or len(raw_name) > 64
                or any(character not in _HEADER_NAME_BYTES for character in raw_name)
            ):
                raise _ProxyRejection(400, "malformed_request")
            name = raw_name.decode("ascii").lower()
            if name in headers:
                raise _ProxyRejection(400, "malformed_request")
            value = raw_value.strip(b" \t")
            if any(character < 0x20 and character != 0x09 for character in value) or 0x7F in value:
                raise _ProxyRejection(400, "malformed_request")
            headers[name] = value
        if "host" not in headers:
            raise _ProxyRejection(400, "malformed_request")
        if set(headers) & _REJECTED_REQUEST_HEADERS:
            raise _ProxyRejection(403, "request_body_blocked")
        return method, target, headers

    def _handle_request(
        self, client: _SocketLike, counts: _TransferCounts
    ) -> tuple[str | None, str | None]:
        head, remainder = self._read_request_head(client)
        method, target, headers = self._parse_request(head)
        if method == "CONNECT":
            return None, self._handle_connect(client, target, headers, remainder, counts)
        if method not in {"GET", "HEAD"}:
            origin = self._origin_from_absolute_target(target)
            web_origin = (
                origin if origin is not None and urlsplit(origin).scheme == "http" else None
            )
            raise _ProxyRejection(405, "method_blocked", web_origin=web_origin)
        if remainder:
            origin = self._origin_from_absolute_target(target)
            web_origin = (
                origin if origin is not None and urlsplit(origin).scheme == "http" else None
            )
            raise _ProxyRejection(403, "request_body_blocked", web_origin=web_origin)
        return self._handle_plain_http(client, method, target, headers, counts), None

    def _origin_from_absolute_target(self, target: str) -> str | None:
        try:
            normalized = normalize_url(target)
        except BrowserContractError:
            return None
        return normalize_origin(
            f"{urlsplit(normalized).scheme}://{urlsplit(normalized).netloc}"
        )

    def _authorized_http_policy(self, target: str, host_header: bytes) -> tuple[_OriginPolicy, str]:
        try:
            normalized = normalize_url(target)
            parsed = urlsplit(normalized)
            origin = normalize_origin(f"{parsed.scheme}://{parsed.netloc}")
        except (BrowserContractError, UnicodeError, ValueError) as exc:
            raise _ProxyRejection(400, "malformed_request") from exc
        if parsed.scheme != "http":
            raise _ProxyRejection(403, "unauthorized_origin")
        policy = self._policies.get(origin)
        if policy is None or policy.scheme != "http":
            raise _ProxyRejection(403, "unauthorized_origin", web_origin=origin)
        try:
            host_value = host_header.decode("ascii")
            host_origin = normalize_origin(f"http://{host_value}")
        except (BrowserContractError, UnicodeDecodeError, ValueError) as exc:
            raise _ProxyRejection(400, "malformed_request", web_origin=origin) from exc
        if host_origin != origin:
            raise _ProxyRejection(403, "unauthorized_origin", web_origin=origin)
        return policy, normalized

    def _handle_plain_http(
        self,
        client: _SocketLike,
        method: str,
        target: str,
        headers: dict[str, bytes],
        counts: _TransferCounts,
    ) -> str:
        policy, normalized = self._authorized_http_policy(target, headers["host"])
        parsed = urlsplit(normalized)
        request_target = parsed.path or "/"
        if parsed.query:
            request_target += "?" + parsed.query
        authority = policy.hostname if policy.port == 80 else f"{policy.hostname}:{policy.port}"
        outbound = bytearray(
            f"{method} {request_target} HTTP/1.1\r\nHost: {authority}\r\n".encode("ascii")
        )
        for name in sorted(set(headers) & _FORWARDED_REQUEST_HEADERS):
            outbound.extend(name.encode("ascii"))
            outbound.extend(b": ")
            outbound.extend(headers[name])
            outbound.extend(b"\r\n")
        outbound.extend(b"Connection: close\r\n\r\n")

        upstream = self._connect(policy)
        try:
            self._consume_transfer(len(outbound), True, counts)
            self._set_timeout(upstream, self._limits.idle_timeout_sec)
            upstream.sendall(bytes(outbound))
            while True:
                try:
                    chunk = self._recv_transfer(upstream, False, counts)
                except socket.timeout as exc:
                    raise _ProxyRejection(
                        504,
                        "deadline",
                        web_origin=policy.origin,
                        response_started=counts.origin_to_client > 0,
                    ) from exc
                if not chunk:
                    break
                self._set_timeout(client, self._limits.idle_timeout_sec)
                client.sendall(chunk)
        except _ProxyRejection as exc:
            if exc.web_origin is None and exc.connect_authority is None:
                exc.web_origin = policy.origin
            exc.response_started = counts.origin_to_client > 0
            exc.egress_performed = True
            raise
        except (OSError, socket.timeout) as exc:
            raise _ProxyRejection(
                502,
                "upstream_failure",
                web_origin=policy.origin,
                response_started=counts.origin_to_client > 0,
                egress_performed=True,
            ) from exc
        except Exception as exc:
            raise _ProxyRejection(
                502,
                "upstream_failure",
                web_origin=policy.origin,
                response_started=counts.origin_to_client > 0,
                egress_performed=True,
            ) from exc
        finally:
            self._release_upstream(upstream)
            try:
                upstream.close()
            except Exception:
                pass
        return policy.origin

    def _connect_authority(
        self, target: str, host_header: bytes
    ) -> tuple[_OriginPolicy, str]:
        # CONNECT authority-form always has an explicit port.  The configured
        # HTTPS origin selects policy, but host evidence retains only the
        # independently observed transport authority.
        if target.count(":") != 1:
            raise _ProxyRejection(400, "malformed_request")
        raw_host, raw_port = target.rsplit(":", 1)
        if not raw_host or not raw_port.isdigit():
            raise _ProxyRejection(400, "malformed_request")
        port = int(raw_port)
        if not 1 <= port <= 65535:
            raise _ProxyRejection(400, "malformed_request")
        try:
            origin = normalize_origin(f"https://{raw_host}:{port}")
        except BrowserContractError as exc:
            raise _ProxyRejection(400, "malformed_request") from exc
        hostname = urlsplit(origin).hostname
        if hostname is None:
            raise _ProxyRejection(400, "malformed_request")
        authority = f"{hostname}:{port}"
        policy = self._policies.get(origin)
        if policy is None or policy.scheme != "https" or policy.port != port:
            raise _ProxyRejection(
                403, "unauthorized_origin", connect_authority=authority
            )
        try:
            host_value = host_header.decode("ascii")
            host_origin = normalize_origin(f"https://{host_value}")
        except (BrowserContractError, UnicodeDecodeError, ValueError) as exc:
            raise _ProxyRejection(
                400, "malformed_request", connect_authority=authority
            ) from exc
        if host_origin != origin:
            raise _ProxyRejection(
                403, "unauthorized_origin", connect_authority=authority
            )
        return policy, authority

    def _handle_connect(
        self,
        client: _SocketLike,
        target: str,
        headers: dict[str, bytes],
        remainder: bytes,
        counts: _TransferCounts,
    ) -> str:
        policy, authority = self._connect_authority(target, headers["host"])
        upstream = self._connect(policy, connect_authority=authority)
        response_started = False
        try:
            self._set_timeout(client, self._limits.idle_timeout_sec)
            client.sendall(
                b"HTTP/1.1 200 Connection Established\r\n"
                b"Proxy-Agent: Cindermote-Browser-Egress/1\r\n\r\n"
            )
            response_started = True
            if remainder:
                self._consume_transfer(len(remainder), True, counts)
                self._set_timeout(upstream, self._limits.idle_timeout_sec)
                upstream.sendall(remainder)
            self._relay_tunnel(client, upstream, counts, authority)
        except _ProxyRejection as exc:
            exc.web_origin = None
            exc.connect_authority = authority
            exc.response_started = response_started or exc.response_started
            exc.egress_performed = True
            raise
        except (OSError, socket.timeout) as exc:
            raise _ProxyRejection(
                502,
                "upstream_failure",
                connect_authority=authority,
                response_started=response_started,
                egress_performed=True,
            ) from exc
        except Exception as exc:
            raise _ProxyRejection(
                502,
                "upstream_failure",
                connect_authority=authority,
                response_started=response_started,
                egress_performed=True,
            ) from exc
        finally:
            self._release_upstream(upstream)
            try:
                upstream.close()
            except Exception:
                pass
        return authority

    def _connect(
        self,
        policy: _OriginPolicy,
        *,
        connect_authority: str | None = None,
    ) -> _SocketLike:
        destination = (
            {"web_origin": policy.origin}
            if connect_authority is None
            else {"connect_authority": connect_authority}
        )
        if self._byte_budget.remaining <= 0:
            raise _ProxyRejection(503, "byte_limit", **destination)
        last_error: BaseException | None = None
        for address in policy.addresses:
            timeout = min(
                float(self._limits.connect_timeout_sec),
                self._remaining_time(),
            )
            try:
                upstream = self._connector(address, policy.port, timeout)
            except (OSError, socket.timeout) as exc:
                last_error = exc
                continue
            try:
                peer_value = upstream.getpeername()
                if (
                    not isinstance(peer_value, tuple)
                    or len(peer_value) < 2
                    or not isinstance(peer_value[1], int)
                    or isinstance(peer_value[1], bool)
                ):
                    raise ValueError("peer address is missing")
                peer = validate_resolved_address(peer_value[0])
                expected = validate_resolved_address(address)
                if (
                    peer != expected
                    or peer not in policy.addresses
                    or peer_value[1] != policy.port
                ):
                    raise BrowserContractError("connected peer is not pinned")
                self._remaining_time()
            except (BrowserContractError, TypeError, ValueError, OSError) as exc:
                upstream.close()
                raise _ProxyRejection(
                    502,
                    "peer_mismatch",
                    **destination,
                    egress_performed=True,
                ) from exc
            with self._state_lock:
                if self._closed:
                    try:
                        upstream.close()
                    except OSError:
                        pass
                    raise _ProxyRejection(
                        503,
                        "proxy_closed",
                        **destination,
                        egress_performed=True,
                    )
                self._active_upstreams[id(upstream)] = upstream
            return upstream
        raise _ProxyRejection(502, "upstream_failure", **destination) from last_error

    def _release_upstream(self, upstream: _SocketLike) -> None:
        with self._state_lock:
            self._active_upstreams.pop(id(upstream), None)

    def _consume_transfer(
        self,
        count: int,
        client_to_origin: bool,
        local: _TransferCounts,
    ) -> None:
        self._remaining_time()
        self._byte_budget.consume(count)
        if client_to_origin:
            local.client_to_origin += count
        else:
            local.origin_to_client += count

    def _recv_transfer(
        self,
        endpoint: _SocketLike,
        client_to_origin: bool,
        local: _TransferCounts,
    ) -> bytes:
        self._remaining_time()
        reservation = self._byte_budget.reserve(_IO_CHUNK_BYTES)
        try:
            self._set_timeout(endpoint, self._limits.idle_timeout_sec)
            chunk = endpoint.recv(reservation)
        except BaseException:
            self._byte_budget.cancel_reservation(reservation)
            raise
        self._byte_budget.commit_reservation(reservation, len(chunk))
        if client_to_origin:
            local.client_to_origin += len(chunk)
        else:
            local.origin_to_client += len(chunk)
        # If authority was revoked during the blocking read, do not forward the
        # newly received bytes across the other side of the boundary.
        self._remaining_time()
        return chunk

    def _relay_tunnel(
        self,
        client: _SocketLike,
        upstream: _SocketLike,
        counts: _TransferCounts,
        connect_authority: str,
    ) -> None:
        selector = selectors.DefaultSelector()
        selector.register(client, selectors.EVENT_READ, (upstream, True))
        selector.register(upstream, selectors.EVENT_READ, (client, False))
        open_readers = 2
        last_activity = self._clock()
        try:
            while open_readers:
                remaining = self._remaining_time()
                idle_remaining = (
                    last_activity + float(self._limits.idle_timeout_sec) - self._clock()
                )
                if idle_remaining <= 0:
                    raise _ProxyRejection(
                        504,
                        "deadline",
                        connect_authority=connect_authority,
                        response_started=True,
                    )
                events = selector.select(
                    timeout=min(
                        remaining,
                        idle_remaining,
                        _TUNNEL_POLL_INTERVAL_SEC,
                    )
                )
                if not events:
                    # A bounded poll is also the deterministic shutdown wakeup
                    # for selector implementations that do not wake when an fd
                    # is closed by another thread.  Empty does not itself mean
                    # the idle/deadline budget expired.
                    self._remaining_time()
                    if (
                        last_activity + float(self._limits.idle_timeout_sec)
                        <= self._clock()
                    ):
                        raise _ProxyRejection(
                            504,
                            "deadline",
                            connect_authority=connect_authority,
                            response_started=True,
                        )
                    continue
                for key, _mask in events:
                    source = key.fileobj
                    destination, client_to_origin = key.data
                    try:
                        chunk = self._recv_transfer(
                            source,
                            client_to_origin,
                            counts,
                        )
                    except socket.timeout as exc:
                        raise _ProxyRejection(
                            504,
                            "deadline",
                            connect_authority=connect_authority,
                            response_started=True,
                        ) from exc
                    if not chunk:
                        selector.unregister(source)
                        open_readers -= 1
                        try:
                            destination.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        continue
                    self._set_timeout(destination, self._limits.idle_timeout_sec)
                    destination.sendall(chunk)
                    last_activity = self._clock()
        finally:
            selector.close()


__all__ = [
    "BrowserEgressClosed",
    "BrowserEgressConfigurationError",
    "BrowserEgressError",
    "BrowserEgressProxy",
    "BrowserEgressStartupError",
    "ProxyLimits",
]
