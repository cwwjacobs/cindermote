#!/usr/bin/env python3
"""Trusted passive Chromium evidence collector for the Firecracker guest.

The collector is a separate in-guest trust domain from the unprivileged
Chromium process. It exposes one fixed vsock port to the host, controls a
loopback-only DevTools endpoint, and emits metadata-only evidence. Page text,
DOM content, console strings, and screenshots never cross the VM boundary.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import http.client
import json
import os
import secrets
import signal
import socket
import struct
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


AGENT_VERSION = "cindermote-browser-agent/1"
VSOCK_PORT = 52
MAX_CHANNEL_LINE = 4 * 1024 * 1024
MAX_WS_MESSAGE = 8 * 1024 * 1024
MAX_CDP_COMMANDS = 50_000
MAX_ATTESTATION_CHARS = 512 * 1024
MAX_ATTESTATION_NODES = 10_000
PR_SET_DUMPABLE = 4

# Fetch.requestPaused reports Chromium's network resource classification.  A
# request is only passive when both its method and its resource type are on an
# explicit allowlist.  In particular, WebSocket and EventSource begin as GET
# requests but create bidirectional or long-lived application channels after
# their handshake.  Unknown/future Chromium resource types must fail closed.
PASSIVE_RESOURCE_TYPES = frozenset(
    {
        "Document",
        "Stylesheet",
        "Image",
        "Media",
        "Font",
        "Script",
        "TextTrack",
        "XHR",
        "Fetch",
        "Prefetch",
        "Manifest",
        "SignedExchange",
    }
)

CDP_SETUP_COMMANDS: tuple[tuple[str, dict[str, Any] | None], ...] = (
    ("Page.enable", None),
    ("Page.setLifecycleEventsEnabled", {"enabled": True}),
    (
        "Network.enable",
        {"maxTotalBufferSize": 1048576, "maxResourceBufferSize": 262144},
    ),
    ("Network.setCacheDisabled", {"cacheDisabled": True}),
    ("Network.setBypassServiceWorker", {"bypass": True}),
    ("Runtime.enable", None),
    ("Log.enable", None),
    ("Security.enable", None),
    (
        "Target.setAutoAttach",
        {
            "autoAttach": True,
            "waitForDebuggerOnStart": True,
            "flatten": True,
            # CDP's implicit filter excludes both browser and tab targets.
            # Keep the browser target excluded but include tab plus every
            # other related child so a popup cannot run outside the pause.
            "filter": [{"type": "browser", "exclude": True}, {}],
        },
    ),
    ("Target.setDiscoverTargets", {"discover": True}),
    ("Page.setInterceptFileChooserDialog", {"enabled": True}),
    ("Fetch.enable", {"patterns": [{"urlPattern": "*", "requestStage": "Request"}]}),
    ("Browser.setDownloadBehavior", {"behavior": "deny", "eventsEnabled": True}),
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from browser_contract import (  # noqa: E402
    EVIDENCE_VERSION,
    BrowserContractError,
    is_authorized_url,
    origin_for_url,
    validate_probe_request,
)


class AgentError(RuntimeError):
    pass


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _hash_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _disable_collector_dumpability() -> None:
    if os.geteuid() != 0:
        raise AgentError("evidence collector must run in its dedicated root trust domain")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        raise AgentError("could not disable evidence collector dumpability")


def _drop_browser_privileges() -> None:
    os.setgroups([])
    os.setgid(1000)
    os.setuid(1000)
    os.umask(0o077)


def _read_json_line(stream: Any) -> dict[str, Any]:
    line = stream.readline(MAX_CHANNEL_LINE + 1)
    if not line or len(line) > MAX_CHANNEL_LINE or not line.endswith(b"\n"):
        raise AgentError("invalid host control message")
    try:
        value = json.loads(line)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AgentError("malformed host control message") from exc
    if not isinstance(value, dict):
        raise AgentError("host control message must be an object")
    return value


def _write_json_line(stream: Any, value: dict[str, Any]) -> None:
    encoded = _canonical_json(value)
    if len(encoded) > MAX_CHANNEL_LINE:
        raise AgentError("guest result exceeds channel budget")
    stream.write(encoded + b"\n")
    stream.flush()


class Evidence:
    def __init__(self, max_events: int) -> None:
        self.max_events = max_events
        self.events: list[dict[str, Any]] = []
        self.sequences: defaultdict[str, int] = defaultdict(int)
        self.complete = {"browser": False, "cdp": False, "egress": False, "vm": False}
        self.truncated = False

    def add(
        self,
        source: str,
        kind: str,
        disposition: str,
        origin: str | None = None,
    ) -> None:
        if len(self.events) >= self.max_events:
            self.truncated = True
            return
        sequence = self.sequences[source]
        self.sequences[source] += 1
        self.events.append(
            {
                "sequence": sequence,
                "source": source,
                "kind": kind,
                "origin": origin,
                "disposition": disposition,
            }
        )

    def bundle(self) -> dict[str, Any]:
        if self.truncated:
            self.add("cdp", "telemetry_loss", "observed")
            self.complete["cdp"] = False
        return {
            "evidence_version": EVIDENCE_VERSION,
            "events": self.events,
            "streams": {
                source: {
                    "complete": bool(self.complete[source]),
                    "event_count": int(self.sequences[source]),
                }
                for source in ("browser", "cdp", "egress", "vm")
            },
        }


class WebSocket:
    """Small RFC 6455 client sufficient for the local Chromium CDP socket."""

    def __init__(self, host: str, port: int, path: str, deadline: float) -> None:
        self.socket = socket.create_connection((host, port), timeout=max(0.1, deadline - time.monotonic()))
        self.deadline = deadline
        self.buffer = bytearray()
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode("ascii")
        self.socket.sendall(request)
        header = self._read_until(b"\r\n\r\n", 32 * 1024)
        lines = header.split(b"\r\n")
        if not lines or b" 101 " not in lines[0]:
            raise AgentError("CDP websocket upgrade failed")
        expected = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()
        )
        headers: dict[bytes, bytes] = {}
        for line in lines[1:]:
            if b":" in line:
                name, value = line.split(b":", 1)
                headers[name.strip().lower()] = value.strip()
        if headers.get(b"sec-websocket-accept") != expected:
            raise AgentError("CDP websocket accept key mismatch")

    def _timeout(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("browser probe deadline expired")
        return remaining

    def _recv(self, count: int) -> bytes:
        while len(self.buffer) < count:
            self.socket.settimeout(self._timeout())
            chunk = self.socket.recv(min(65536, count - len(self.buffer)))
            if not chunk:
                raise AgentError("CDP websocket closed")
            self.buffer.extend(chunk)
        value = bytes(self.buffer[:count])
        del self.buffer[:count]
        return value

    def _read_until(self, marker: bytes, limit: int) -> bytes:
        while marker not in self.buffer:
            if len(self.buffer) >= limit:
                raise AgentError("CDP websocket header too large")
            self.socket.settimeout(self._timeout())
            chunk = self.socket.recv(min(4096, limit - len(self.buffer)))
            if not chunk:
                raise AgentError("CDP websocket closed during upgrade")
            self.buffer.extend(chunk)
        index = self.buffer.index(marker) + len(marker)
        value = bytes(self.buffer[:index])
        del self.buffer[:index]
        return value

    def send_json(self, value: dict[str, Any]) -> None:
        payload = _canonical_json(value)
        if len(payload) > MAX_WS_MESSAGE:
            raise AgentError("CDP command exceeds message budget")
        mask = os.urandom(4)
        length = len(payload)
        if length < 126:
            header = bytes((0x81, 0x80 | length))
        elif length <= 0xFFFF:
            header = bytes((0x81, 0xFE)) + struct.pack("!H", length)
        else:
            header = bytes((0x81, 0xFF)) + struct.pack("!Q", length)
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self.socket.sendall(header + mask + masked)

    def receive_json(self) -> dict[str, Any]:
        fragments = bytearray()
        expecting_continuation = False
        while True:
            first, second = self._recv(2)
            final = bool(first & 0x80)
            opcode = first & 0x0F
            masked = bool(second & 0x80)
            if masked:
                raise AgentError("CDP server sent a masked frame")
            length = second & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._recv(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._recv(8))[0]
            if length > MAX_WS_MESSAGE or len(fragments) + length > MAX_WS_MESSAGE:
                raise AgentError("CDP websocket message exceeds budget")
            payload = self._recv(length)
            if opcode == 0x8:
                raise AgentError("CDP websocket closed")
            if opcode == 0x9:
                self._send_control(0xA, payload)
                continue
            if opcode == 0xA:
                continue
            if opcode == 0x1 and not expecting_continuation:
                fragments.extend(payload)
                expecting_continuation = not final
            elif opcode == 0x0 and expecting_continuation:
                fragments.extend(payload)
                expecting_continuation = not final
            else:
                raise AgentError("unexpected CDP websocket opcode")
            if not expecting_continuation:
                try:
                    value = json.loads(fragments)
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    raise AgentError("malformed CDP JSON") from exc
                if not isinstance(value, dict):
                    raise AgentError("CDP message must be an object")
                return value

    def _send_control(self, opcode: int, payload: bytes) -> None:
        if len(payload) > 125:
            raise AgentError("invalid websocket control payload")
        mask = os.urandom(4)
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self.socket.sendall(bytes((0x80 | opcode, 0x80 | len(payload))) + mask + masked)

    def close(self) -> None:
        try:
            self.socket.close()
        except OSError:
            pass


class CDP:
    def __init__(self, websocket: WebSocket, evidence: Evidence, request: dict[str, Any]) -> None:
        self.websocket = websocket
        self.evidence = evidence
        self.request = request
        self.next_id = 1
        self.responses: dict[int, dict[str, Any]] = {}
        self.console_events = 0
        self.loaded_lifecycles: set[tuple[str, str]] = set()
        self.main_frame_id: str | None = None

    def command(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if self.next_id > MAX_CDP_COMMANDS:
            raise AgentError("CDP command budget exhausted")
        identifier = self.next_id
        self.next_id += 1
        message: dict[str, Any] = {"id": identifier, "method": method}
        if params is not None:
            message["params"] = params
        self.websocket.send_json(message)
        while True:
            buffered = self.responses.pop(identifier, None)
            if buffered is not None:
                incoming = buffered
            else:
                incoming = self.websocket.receive_json()
            incoming_id = incoming.get("id")
            if isinstance(incoming_id, int) and incoming_id != identifier:
                if len(self.responses) >= 1024 or incoming_id in self.responses:
                    raise AgentError("CDP response buffer is inconsistent")
                self.responses[incoming_id] = incoming
                continue
            if incoming_id == identifier:
                if "error" in incoming:
                    raise AgentError(f"CDP command failed: {method}")
                result = incoming.get("result", {})
                if not isinstance(result, dict):
                    raise AgentError("CDP command result is malformed")
                return result
            self.handle_event(incoming)

    def handle_event(self, message: dict[str, Any]) -> None:
        method = message.get("method")
        params = message.get("params", {})
        if not isinstance(method, str) or not isinstance(params, dict):
            return
        if method == "Fetch.requestPaused":
            self._handle_paused(params)
        elif method == "Page.lifecycleEvent":
            frame_id = params.get("frameId")
            loader_id = params.get("loaderId")
            if (
                params.get("name") == "load"
                and isinstance(frame_id, str)
                and isinstance(loader_id, str)
            ):
                self.loaded_lifecycles.add((frame_id, loader_id))
        elif method == "Page.frameNavigated":
            frame = params.get("frame", {})
            if isinstance(frame, dict) and not frame.get("parentId"):
                self.main_frame_id = frame.get("id") if isinstance(frame.get("id"), str) else None
                self._record_url("navigation", "committed", frame.get("url"))
        elif method == "Network.requestWillBeSent":
            if params.get("redirectResponse") is not None:
                request = params.get("request", {})
                self._record_url("redirect", "followed", request.get("url") if isinstance(request, dict) else None)
        elif method in {"Page.downloadWillBegin", "Browser.downloadWillBegin"}:
            self.evidence.add("cdp", "download_attempt", "attempted")
        elif method == "Page.fileChooserOpened":
            self.evidence.add("cdp", "file_upload_attempt", "attempted")
        elif method == "Page.windowOpen":
            # This event is emitted for window.open(), target=_blank links, and
            # form-driven windows even when Chromium's own popup blocker stops
            # target creation.  Record only the attempt; if a target is
            # created, auto-attach independently freezes and closes it below.
            self.evidence.add("cdp", "popup_attempt", "attempted")
        elif method == "Target.targetCreated":
            info = params.get("targetInfo", {})
            if isinstance(info, dict) and info.get("type") == "page" and info.get("openerId"):
                self.evidence.add("cdp", "popup_attempt", "attempted")
        elif method == "Target.attachedToTarget":
            self._close_attached_child(params)
        elif method in {"Runtime.consoleAPICalled", "Runtime.exceptionThrown", "Log.entryAdded"}:
            self.console_events += 1
        elif method == "Security.visibleSecurityStateChanged":
            state = params.get("visibleSecurityState", {})
            if isinstance(state, dict):
                mixed = state.get("securityStateIssueIds", [])
                if isinstance(mixed, list) and any("mixed" in str(item).lower() for item in mixed):
                    self.evidence.add("cdp", "mixed_content", "observed")

    def _safe_origin(self, url: Any) -> str | None:
        if not isinstance(url, str):
            return None
        try:
            return origin_for_url(url)
        except BrowserContractError:
            return None

    def _record_url(self, kind: str, disposition: str, url: Any) -> None:
        if isinstance(url, str) and url in {"about:blank", "about:srcdoc"}:
            return
        origin = self._safe_origin(url)
        if origin is None:
            self.evidence.add("cdp", "active_interaction", "attempted")
            return
        self.evidence.add("cdp", kind, disposition, origin)

    def _close_attached_child(self, params: dict[str, Any]) -> None:
        """Close an auto-attached child while Chromium still has it paused.

        ``Target.setAutoAttach(waitForDebuggerOnStart=true)`` is installed on
        the controlled page before navigation with an explicit filter that
        includes tab targets.  Therefore every event handled
        here represents a child target which must remain suspended until it is
        destroyed.  We deliberately never issue Runtime.runIfWaitingForDebugger
        for a child.  Any ambiguity is a loss of the passive-execution boundary
        and terminates the probe.
        """

        info = params.get("targetInfo")
        session_id = params.get("sessionId")
        waiting = params.get("waitingForDebugger")
        if not isinstance(info, dict) or not isinstance(session_id, str) or not session_id:
            self.evidence.add("cdp", "telemetry_loss", "observed")
            raise AgentError("auto-attached child target metadata is malformed")
        target_id = info.get("targetId")
        target_type = info.get("type")
        if (
            not isinstance(target_id, str)
            or not target_id
            or len(target_id) > 256
            or not isinstance(target_type, str)
            or not target_type
            or len(target_type) > 128
            or not isinstance(waiting, bool)
        ):
            self.evidence.add("cdp", "telemetry_loss", "observed")
            raise AgentError("auto-attached child target metadata is malformed")

        if target_type in {"page", "tab"}:
            self.evidence.add("cdp", "popup_attempt", "blocked")
        else:
            self.evidence.add("cdp", "active_interaction", "blocked")

        try:
            result = self.command("Target.closeTarget", {"targetId": target_id})
        except AgentError:
            self.evidence.add("cdp", "telemetry_loss", "observed")
            raise
        if result.get("success") is not True:
            self.evidence.add("cdp", "telemetry_loss", "observed")
            raise AgentError("auto-attached child target could not be closed")
        if waiting is not True:
            # The child is closed, but it may already have executed.  Evidence
            # from this run cannot establish passive behavior.
            self.evidence.add("cdp", "telemetry_loss", "observed")
            raise AgentError("auto-attached child target was not debugger-paused")

    def _handle_paused(self, params: dict[str, Any]) -> None:
        request_id = params.get("requestId")
        request = params.get("request", {})
        if not isinstance(request_id, str) or not isinstance(request, dict):
            self.evidence.add("cdp", "telemetry_loss", "observed")
            return
        url = request.get("url")
        method = request.get("method")
        resource_type = params.get("resourceType")
        passive_resource = (
            isinstance(resource_type, str) and resource_type in PASSIVE_RESOURCE_TYPES
        )
        allowed = False
        origin: str | None = None
        if isinstance(url, str):
            scheme = urlsplit(url).scheme.lower()
            if (
                scheme in {"about", "blob", "data"}
                and method in {"GET", "HEAD"}
                and passive_resource
            ):
                allowed = True
            elif scheme in {"http", "https"}:
                origin = self._safe_origin(url)
                try:
                    allowed = (
                        method in {"GET", "HEAD"}
                        and passive_resource
                        and is_authorized_url(url, self.request["authorized_origins"])
                    )
                except BrowserContractError:
                    allowed = False
        if method not in {"GET", "HEAD"} or not passive_resource:
            self.evidence.add("cdp", "active_interaction", "attempted")
        if origin is not None:
            self.evidence.add(
                "cdp", "network_request", "allowed" if allowed else "blocked", origin
            )
        elif not allowed:
            self.evidence.add("cdp", "active_interaction", "attempted")
        action = "Fetch.continueRequest" if allowed else "Fetch.failRequest"
        arguments = {"requestId": request_id}
        if not allowed:
            arguments["errorReason"] = "BlockedByClient"
        try:
            self.command(action, arguments)
        except AgentError:
            self.evidence.add("cdp", "telemetry_loss", "observed")

    def pump_until_loaded(self, frame_id: str, loader_id: str, deadline: float) -> None:
        expected = (frame_id, loader_id)
        while expected not in self.loaded_lifecycles and time.monotonic() < deadline:
            try:
                message = self.websocket.receive_json()
            except socket.timeout:
                continue
            incoming_id = message.get("id")
            if isinstance(incoming_id, int):
                if len(self.responses) >= 1024 or incoming_id in self.responses:
                    raise AgentError("CDP response buffer is inconsistent")
                self.responses[incoming_id] = message
            else:
                self.handle_event(message)
        if expected not in self.loaded_lifecycles:
            raise TimeoutError("target page lifecycle deadline expired")


def _wait_devtools(profile: Path, process: subprocess.Popen[bytes], deadline: float) -> tuple[int, str]:
    marker = profile / "DevToolsActivePort"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AgentError("Chromium exited before DevTools became ready")
        try:
            lines = marker.read_text(encoding="ascii").splitlines()
        except OSError:
            time.sleep(0.02)
            continue
        if len(lines) >= 2 and lines[0].isdigit() and lines[1].startswith("/"):
            return int(lines[0]), lines[1]
        time.sleep(0.02)
    raise TimeoutError("Chromium DevTools startup timed out")


def _page_websocket(port: int, deadline: float) -> str:
    while time.monotonic() < deadline:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=max(0.1, deadline - time.monotonic()))
        try:
            connection.request("GET", "/json/list")
            response = connection.getresponse()
            body = response.read(1024 * 1024)
            if response.status != 200:
                raise AgentError("DevTools target list failed")
            values = json.loads(body)
            for value in values if isinstance(values, list) else []:
                if isinstance(value, dict) and value.get("type") == "page":
                    endpoint = value.get("webSocketDebuggerUrl")
                    if isinstance(endpoint, str):
                        return endpoint
        except (OSError, ValueError, json.JSONDecodeError):
            time.sleep(0.02)
        finally:
            connection.close()
    raise TimeoutError("DevTools page target timed out")


def _sandbox_active(browser_pid: int) -> bool:
    descendants = {browser_pid}
    changed = True
    while changed:
        changed = False
        for status_path in Path("/proc").glob("[0-9]*/status"):
            try:
                text = status_path.read_text(encoding="ascii", errors="replace")
            except OSError:
                continue
            values = dict(
                line.split(":", 1) for line in text.splitlines() if ":" in line
            )
            try:
                pid = int(status_path.parent.name)
                ppid = int(values.get("PPid", "-1").strip())
            except ValueError:
                continue
            if ppid in descendants and pid not in descendants:
                descendants.add(pid)
                changed = True
    renderers = []
    for pid in descendants:
        try:
            command = Path(f"/proc/{pid}/cmdline").read_bytes()
            status = Path(f"/proc/{pid}/status").read_text(encoding="ascii", errors="replace")
        except OSError:
            continue
        if b"--type=renderer" not in command:
            continue
        fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
        uid = fields.get("Uid", "").split()
        seccomp = fields.get("Seccomp", "").strip()
        renderers.append(bool(uid and uid[0] == "1000" and seccomp == "2"))
    return bool(renderers) and all(renderers)


_PAGE_ATTESTATION = r"""
(() => {
  const marker = /(ignore\s+(all|any|the|previous)|system\s+message|developer\s+message|assistant\s+instruction|tool\s+call|jailbreak|override\s+policy)/i;
  let visible = 0, hidden = 0, scanned = 0, scanTruncated = false;
  const walker = document.createTreeWalker(document.body || document.documentElement, NodeFilter.SHOW_ELEMENT);
  let element;
  while ((element = walker.nextNode()) !== null) {
    if (scanned >= 10000) { scanTruncated = true; break; }
    scanned += 1;
    const text = (element.innerText || element.textContent || '').slice(0, 8192);
    if (!marker.test(text)) continue;
    let childMarker = false, childrenChecked = 0;
    for (const child of element.children) {
      if (childrenChecked >= 256) { scanTruncated = true; break; }
      childrenChecked += 1;
      if (marker.test((child.innerText || child.textContent || '').slice(0, 8192))) {
        childMarker = true;
        break;
      }
    }
    if (childMarker) continue;
    const style = getComputedStyle(element);
    const rect = element.getBoundingClientRect();
    const isVisible = style.display !== 'none' && style.visibility !== 'hidden' &&
      Number(style.opacity || '1') > 0 && parseFloat(style.fontSize || '0') > 0 &&
      rect.width > 0 && rect.height > 0 && rect.bottom > 0 && rect.right > 0 &&
      rect.top < innerHeight && rect.left < innerWidth &&
      element.getAttribute('aria-hidden') !== 'true';
    if (isVisible) visible += 1; else hidden += 1;
  }
  const fullDom = document.documentElement ? document.documentElement.outerHTML : '';
  const fullVisibleText = document.body ? document.body.innerText : '';
  return {
    dom: fullDom.slice(0, 524288),
    visible_text: fullVisibleText.slice(0, 524288),
    dom_truncated: fullDom.length > 524288,
    visible_text_truncated: fullVisibleText.length > 524288,
    node_scan_truncated: scanTruncated,
    marker_visible_count: visible,
    marker_hidden_count: hidden
  };
})()
"""


def _run_probe(wrapper: dict[str, Any], evidence: Evidence) -> dict[str, Any]:
    request = validate_probe_request(wrapper.get("probe_request"))
    runtime = wrapper.get("runtime")
    if not isinstance(runtime, dict) or set(runtime) != {"nonce", "proxy_url"}:
        raise AgentError("invalid guest runtime contract")
    nonce = runtime.get("nonce")
    proxy_url = runtime.get("proxy_url")
    if not isinstance(nonce, str) or len(nonce) != 64:
        raise AgentError("invalid job nonce")
    if proxy_url != "http://169.254.250.1:18080":
        raise AgentError("unexpected egress proxy endpoint")

    deadline = time.monotonic() + request["budgets"]["wall_clock_sec"]
    profile = Path("/home/probe/profile")
    profile.mkdir(mode=0o700)
    cache = Path("/home/probe/cache")
    cache.mkdir(mode=0o700)
    os.chown(profile, 1000, 1000)
    os.chown(cache, 1000, 1000)
    evidence.add("browser", "lifecycle", "started")
    command = [
        "/usr/bin/chromium",
        "--headless",
        f"--user-data-dir={profile}",
        "--remote-debugging-address=127.0.0.1",
        "--remote-debugging-port=0",
        f"--proxy-server={proxy_url}",
        "--proxy-bypass-list=<-loopback>",
        "--disable-background-networking",
        "--disable-breakpad",
        "--disable-component-update",
        "--disable-default-apps",
        "--disable-extensions",
        "--disable-features=AsyncDns,DnsOverHttps,MediaRouter",
        "--disable-sync",
        "--deny-permission-prompts",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--metrics-recording-only",
        "--no-default-browser-check",
        "--no-first-run",
        "--no-pings",
        "--window-size=1280,720",
        "about:blank",
    ]
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        preexec_fn=_drop_browser_privileges,
        env={
            "HOME": "/home/probe",
            "USER": "probe",
            "LOGNAME": "probe",
            "LANG": "C.UTF-8",
            "PATH": "/usr/bin:/bin",
            "TMPDIR": "/tmp",
            "XDG_CACHE_HOME": "/home/probe/cache",
            "XDG_CONFIG_HOME": "/home/probe/profile",
        },
    )
    websocket: WebSocket | None = None
    artifacts: dict[str, Any] = {"raw_retained": False}
    try:
        port, _ = _wait_devtools(profile, process, deadline)
        endpoint = _page_websocket(port, deadline)
        parsed = urlsplit(endpoint)
        if parsed.scheme != "ws" or parsed.hostname != "127.0.0.1" or parsed.port != port:
            raise AgentError("DevTools exposed an unexpected websocket endpoint")
        websocket = WebSocket("127.0.0.1", port, parsed.path, deadline)
        cdp = CDP(websocket, evidence, request)
        for method, params in CDP_SETUP_COMMANDS:
            cdp.command(method, params)
        navigation = cdp.command("Page.navigate", {"url": request["url"]})
        navigation_frame = navigation.get("frameId")
        navigation_loader = navigation.get("loaderId")
        if (
            not isinstance(navigation_frame, str)
            or not isinstance(navigation_loader, str)
            or navigation.get("errorText")
        ):
            raise AgentError("target navigation was not bound to a new loader")
        cdp.pump_until_loaded(navigation_frame, navigation_loader, deadline)
        if cdp.main_frame_id != navigation_frame:
            raise AgentError("committed main frame differs from the target navigation")
        isolated_world = cdp.command(
            "Page.createIsolatedWorld",
            {
                "frameId": navigation_frame,
                "worldName": "cindermote-evidence-v1",
                "grantUniveralAccess": False,
            },
        )
        context_id = isolated_world.get("executionContextId")
        if not isinstance(context_id, int) or isinstance(context_id, bool):
            raise AgentError("isolated evidence world was not created")
        attestation = cdp.command(
            "Runtime.evaluate",
            {
                "expression": _PAGE_ATTESTATION,
                "returnByValue": True,
                "contextId": context_id,
                "timeout": max(1, int((deadline - time.monotonic()) * 1000)),
            },
        )
        remote = attestation.get("result", {})
        value = remote.get("value", {}) if isinstance(remote, dict) else {}
        if not isinstance(value, dict):
            raise AgentError("page attestation result is malformed")
        dom = value.get("dom")
        visible_text = value.get("visible_text")
        if (
            not isinstance(dom, str)
            or not isinstance(visible_text, str)
            or len(dom) > MAX_ATTESTATION_CHARS
            or len(visible_text) > MAX_ATTESTATION_CHARS
        ):
            raise AgentError("page attestation content is malformed")
        truncation_fields = (
            value.get("dom_truncated"),
            value.get("visible_text_truncated"),
            value.get("node_scan_truncated"),
        )
        if any(not isinstance(item, bool) for item in truncation_fields):
            raise AgentError("page attestation truncation state is malformed")
        attestation_complete = not any(truncation_fields)
        if not attestation_complete:
            evidence.add("cdp", "telemetry_loss", "observed")
        artifacts["attestation_complete"] = attestation_complete
        artifacts["dom_sha256"] = hashlib.sha256(
            dom.encode("utf-8", "surrogatepass")
        ).hexdigest()
        artifacts["visible_text_sha256"] = hashlib.sha256(
            visible_text.encode("utf-8", "surrogatepass")
        ).hexdigest()
        visible_count = value.get("marker_visible_count")
        hidden_count = value.get("marker_hidden_count")
        for count in (visible_count, hidden_count):
            if not isinstance(count, int) or isinstance(count, bool) or not 0 <= count <= MAX_ATTESTATION_NODES:
                raise AgentError("page marker count is malformed")
        for _ in range(min(visible_count, 100)):
            evidence.add("cdp", "prompt_marker", "visible")
        for _ in range(min(hidden_count, 100)):
            evidence.add("cdp", "prompt_marker", "hidden")
        screenshot = cdp.command("Page.captureScreenshot", {"format": "png", "fromSurface": True})
        encoded = screenshot.get("data")
        if not isinstance(encoded, str) or len(encoded) > 16 * 1024 * 1024:
            raise AgentError("screenshot result is malformed")
        try:
            artifacts["screenshot_sha256"] = hashlib.sha256(base64.b64decode(encoded, validate=True)).hexdigest()
        except ValueError as exc:
            raise AgentError("screenshot encoding is malformed") from exc
        artifacts["console_event_count"] = cdp.console_events
        sandbox_active = _sandbox_active(process.pid)
        evidence.add("browser", "browser_sandbox", "active" if sandbox_active else "inactive")
        evidence.complete["browser"] = sandbox_active
        evidence.complete["cdp"] = True
        evidence.add("browser", "lifecycle", "stopped")
        return {
            "probe_request_sha256": _hash_json(request),
            "artifacts": artifacts,
            "browser_version": Path("/opt/cindermote/chromium.version").read_text(encoding="utf-8").strip(),
        }
    except BaseException:
        evidence.add("browser", "lifecycle", "failed")
        evidence.add("cdp", "telemetry_loss", "observed")
        evidence.complete["browser"] = False
        evidence.complete["cdp"] = False
        raise
    finally:
        if websocket is not None:
            websocket.close()
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    try:
        _disable_collector_dumpability()
        wrapper = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
        if not isinstance(wrapper, dict):
            raise AgentError("guest request wrapper must be an object")
        runtime = wrapper.get("runtime", {})
        nonce = runtime.get("nonce") if isinstance(runtime, dict) else None
        request = validate_probe_request(wrapper.get("probe_request"))
        evidence = Evidence(request["budgets"]["max_events"])
        if not hasattr(socket, "AF_VSOCK"):
            raise AgentError("guest Python lacks AF_VSOCK")
        listener = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((socket.VMADDR_CID_ANY, VSOCK_PORT))
        listener.listen(1)
        listener.settimeout(10)
        connection, _ = listener.accept()
        listener.close()
        channel = connection.makefile("rwb", buffering=0)
        _write_json_line(
            channel,
            {"type": "hello", "agent_version": AGENT_VERSION, "nonce": nonce},
        )
        control = _read_json_line(channel)
        if control != {"type": "run", "nonce": nonce}:
            raise AgentError("host handshake did not bind the job nonce")
        try:
            metadata = _run_probe(wrapper, evidence)
            result = {
                "type": "result",
                "nonce": nonce,
                "agent_version": AGENT_VERSION,
                "evidence": evidence.bundle(),
                **metadata,
            }
        except BaseException:
            result = {
                "type": "result",
                "nonce": nonce,
                "agent_version": AGENT_VERSION,
                "evidence": evidence.bundle(),
                "error": "guest_probe_failed",
            }
        _write_json_line(channel, result)
        channel.close()
        connection.close()
        return 0 if "error" not in result else 1
    except BaseException:
        return 125


if __name__ == "__main__":
    raise SystemExit(main())
