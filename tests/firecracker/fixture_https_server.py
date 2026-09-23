#!/usr/bin/env python3
"""Operator-controlled HTTPS fixture for the Firecracker competition gate.

Run this on a publicly reachable host behind DNS names covered by the supplied
certificate.  The browser profile intentionally rejects private/special IPs,
so silently redirecting the production probe to localhost would not exercise
the real egress boundary.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import signal
import ssl
import stat
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
COUNTER_KEYS = ("post", "websocket", "popup", "unauthorized")


def _read_token(path: Path) -> str:
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
        raise ValueError("control token file must be a private regular file")
    token = path.read_text(encoding="ascii").strip()
    if TOKEN_PATTERN.fullmatch(token) is None:
        raise ValueError("control token must contain 32-128 URL-safe characters")
    return token


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("fixture origins must be authority-only HTTPS URLs")
    port = parsed.port
    authority = parsed.hostname.lower() if port in {None, 443} else f"{parsed.hostname.lower()}:{port}"
    return f"https://{authority}"


class FixtureState:
    def __init__(
        self,
        token: str,
        primary_origin: str,
        unauthorized_origin: str,
        source_sha256: str,
    ) -> None:
        self.token = token
        self.primary_origin = primary_origin
        self.unauthorized_origin = unauthorized_origin
        self.source_sha256 = source_sha256
        self._counts = {name: 0 for name in COUNTER_KEYS}
        self._lock = threading.Lock()

    def increment(self, name: str) -> None:
        with self._lock:
            self._counts[name] += 1

    def reset(self) -> None:
        with self._lock:
            self._counts = {name: 0 for name in COUNTER_KEYS}

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counts)


class FixtureServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, address: tuple[str, int], state: FixtureState) -> None:
        super().__init__(address, FixtureHandler)
        self.state = state


class FixtureHandler(BaseHTTPRequestHandler):
    server: FixtureServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:
        # Paths can contain attacker-controlled values.  The gate needs counts,
        # not raw access logs.
        return

    def _authorized_control(self) -> bool:
        supplied = self.headers.get("Authorization", "")
        expected = f"Bearer {self.server.state.token}"
        return hmac.compare_digest(supplied, expected)

    def _send(self, status: HTTPStatus, body: bytes, content_type: str) -> None:
        self.send_response(status.value)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'unsafe-inline'; img-src https:; connect-src https: wss:; frame-src 'none'",
        )
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _html(self, script: str = "", body: str = "fixture") -> None:
        payload = (
            "<!doctype html><meta charset=utf-8><title>cindermote fixture</title>"
            f"<main>{body}</main><script>{script}</script>"
        ).encode("utf-8")
        self._send(HTTPStatus.OK, payload, "text/html; charset=utf-8")

    def _reject(self, status: HTTPStatus = HTTPStatus.NOT_FOUND) -> None:
        self._send(status, b"not found\n", "text/plain; charset=utf-8")

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path == "/control/info":
            if not self._authorized_control():
                self._reject(HTTPStatus.FORBIDDEN)
                return
            payload = json.dumps(
                {
                    "schema_version": "cindermote.e2e-fixture/v1",
                    "primary_origin": self.server.state.primary_origin,
                    "unauthorized_origin": self.server.state.unauthorized_origin,
                    "fixture_source_sha256": self.server.state.source_sha256,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            self._send(HTTPStatus.OK, payload, "application/json")
            return
        if path == "/control/counts":
            if not self._authorized_control():
                self._reject(HTTPStatus.FORBIDDEN)
                return
            payload = json.dumps(
                {"schema_version": "cindermote.e2e-fixture/v1", "counts": self.server.state.snapshot()},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            self._send(HTTPStatus.OK, payload, "application/json")
            return
        if path == "/case/clean":
            self._html(body="clean passive navigation")
            return
        if path == "/case/post":
            self._html("fetch('/forbidden/post',{method:'POST',body:'blocked'}).catch(()=>{});")
            return
        if path == "/case/websocket":
            self._html(
                "const u=new URL('/forbidden/ws',location.href);"
                "u.protocol='wss:';try{new WebSocket(u)}catch(e){}"
            )
            return
        if path == "/case/popup":
            self._html("try{window.open('/forbidden/popup','cindermote-child')}catch(e){}")
            return
        if path == "/case/unauthorized":
            target = json.dumps(self.server.state.unauthorized_origin + "/forbidden/unauthorized")
            self._html(f"const i=new Image();i.src={target};document.body.appendChild(i);")
            return
        if path == "/favicon.ico":
            self._send(HTTPStatus.NO_CONTENT, b"", "image/x-icon")
            return
        if path == "/forbidden/ws" and self.headers.get("Upgrade", "").lower() == "websocket":
            self.server.state.increment("websocket")
            self._reject(HTTPStatus.UPGRADE_REQUIRED)
            return
        if path == "/forbidden/popup":
            self.server.state.increment("popup")
            self._html(body="this popup must never load")
            return
        if path == "/forbidden/unauthorized":
            self.server.state.increment("unauthorized")
            self._send(HTTPStatus.OK, b"<svg xmlns='http://www.w3.org/2000/svg'/>", "image/svg+xml")
            return
        self._reject()

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        length_text = self.headers.get("Content-Length", "0")
        try:
            length = int(length_text)
        except ValueError:
            self._reject(HTTPStatus.BAD_REQUEST)
            return
        if not 0 <= length <= 4096:
            self._reject(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return
        if length:
            self.rfile.read(length)
        if path == "/control/reset":
            if not self._authorized_control():
                self._reject(HTTPStatus.FORBIDDEN)
                return
            self.server.state.reset()
            self._send(HTTPStatus.OK, b'{"reset":true}', "application/json")
            return
        if path == "/forbidden/post":
            self.server.state.increment("post")
            self._send(HTTPStatus.OK, b'{"unexpected":true}', "application/json")
            return
        self._reject()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--certificate", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--primary-origin", required=True)
    parser.add_argument("--unauthorized-origin", required=True)
    parser.add_argument("--control-token-file", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    primary = _origin(args.primary_origin)
    unauthorized = _origin(args.unauthorized_origin)
    if primary == unauthorized:
        raise SystemExit("fixture origins must be distinct")
    if (urlsplit(primary).port or 443) != args.port:
        raise SystemExit("primary origin port does not match listener port")
    token = _read_token(args.control_token_file)
    source_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    state = FixtureState(token, primary, unauthorized, source_sha256)
    server = FixtureServer((args.bind, args.port), state)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.certificate, args.private_key)
    server.socket = context.wrap_socket(server.socket, server_side=True)

    def stop(_signum: int, _frame: object) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    print(f"Cindermote HTTPS fixture ready on {primary}", flush=True)
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
