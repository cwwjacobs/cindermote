from __future__ import annotations

import base64
import copy
import json
import signal
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch


PROJECT_DIR = Path(__file__).resolve().parents[2]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

# The production image installs the shared contract beside browser_agent.py.
# Bind the repository copy to that import name for an equivalent unit-test
# environment without creating another source-of-truth copy in guest/.
from mote import browser_contract as _browser_contract  # noqa: E402

sys.modules.setdefault("browser_contract", _browser_contract)

from guest import browser_agent as _browser_agent  # noqa: E402
from guest.browser_agent import (  # noqa: E402
    CDP,
    CDP_SETUP_COMMANDS,
    AgentError,
    Evidence,
    MAX_DOCUMENT_BODY_BYTES,
    MAX_RESPONSE_HEADER_BYTES,
    MAX_RESPONSE_HEADERS,
    MAX_WS_MESSAGE,
    ProbeFailure,
    _failure_code,
    _stop_browser,
)
from mote.browser_contract import make_probe_request  # noqa: E402


class _FakeWebSocket:
    def __init__(self, results: dict[str, dict[str, Any]] | None = None) -> None:
        self.results = {
            "Fetch.getResponseBody": {
                "body": base64.b64encode(b"<html>fixture</html>").decode("ascii"),
                "base64Encoded": True,
            },
            **(results or {}),
        }
        self.sent: list[dict[str, Any]] = []
        self.incoming: list[dict[str, Any]] = []

    def send_json(self, value: dict[str, Any]) -> None:
        self.sent.append(copy.deepcopy(value))
        result = copy.deepcopy(self.results.get(value["method"], {}))
        self.incoming.append({"id": value["id"], "result": result})

    def receive_json(self) -> dict[str, Any]:
        if not self.incoming:
            raise AssertionError("test websocket has no queued CDP response")
        return self.incoming.pop(0)


def _cdp(
    *, results: dict[str, dict[str, Any]] | None = None
) -> tuple[CDP, _FakeWebSocket, Evidence]:
    websocket = _FakeWebSocket(results)
    evidence = Evidence(max_events=100)
    request = make_probe_request("https://example.com/")
    return CDP(websocket, evidence, request), websocket, evidence


def _paused(resource_type: Any = "Document", method: str = "GET") -> dict[str, Any]:
    params: dict[str, Any] = {
        "requestId": "request-1",
        "request": {"url": "https://example.com/resource", "method": method},
    }
    if resource_type is not None:
        params["resourceType"] = resource_type
    return {"method": "Fetch.requestPaused", "params": params}


def _response() -> dict[str, Any]:
    event = _paused()
    event["params"].update({
        "responseStatusCode": 200,
        "responseStatusText": "OK",
        "responseHeaders": [
            {"name": "content-type", "value": "text/html; charset=utf-8"},
            {"name": "content-length", "value": "42"},
        ],
    })
    return event


def _csp_issue(**overrides: Any) -> dict[str, Any]:
    violation = {
        "blockedURL": "wss://example.com/private-path?private-query=1",
        "violatedDirective": "connect-src",
        "isReportOnly": False,
        "contentSecurityPolicyViolationType": "kURLViolation",
    }
    violation.update(overrides)
    return {
        "method": "Audits.issueAdded",
        "params": {"issue": {
            "code": "ContentSecurityPolicyIssue",
            "details": {"contentSecurityPolicyIssueDetails": violation},
        }},
    }


class NativeWebSocketBoundaryTests(unittest.TestCase):
    def test_http2_empty_status_phrase_is_omitted_from_body_fulfillment(self) -> None:
        cdp, websocket, _ = _cdp()
        event = _response()
        event["params"]["responseStatusText"] = ""
        cdp.handle_event(event)
        self.assertEqual(websocket.sent[-1]["method"], "Fetch.fulfillRequest")
        self.assertEqual(websocket.sent[-1]["params"]["responseCode"], 200)
        self.assertNotIn("responsePhrase", websocket.sent[-1]["params"])

    def test_native_audits_and_document_response_interception_are_installed_before_navigation(self) -> None:
        commands = [method for method, _ in CDP_SETUP_COMMANDS]
        self.assertLess(commands.index("Audits.enable"), commands.index("Fetch.enable"))
        fetch = dict(CDP_SETUP_COMMANDS)["Fetch.enable"]
        self.assertIn(
            {"urlPattern": "*", "resourceType": "Document", "requestStage": "Response"},
            fetch["patterns"],
        )
        self.assertNotIn("Page.navigate", commands)

    def test_document_csp_preserves_existing_policy_status_and_exact_body_bytes(self) -> None:
        body = b"<html>private-\xff\xfe-page</html>"
        encoded = base64.b64encode(body).decode("ascii")
        cdp, websocket, evidence = _cdp(results={
            "Fetch.getResponseBody": {"body": encoded, "base64Encoded": True},
        })
        event = _response()
        event["params"].update({"responseStatusCode": 201, "responseStatusText": "Created"})
        original_csp = {"name": "Content-Security-Policy", "value": "script-src 'self'; connect-src 'none'"}
        event["params"]["responseHeaders"].extend([
            original_csp,
            {"name": "set-cookie", "value": "private-cookie=private-value; Secure"},
            {"name": "content-encoding", "value": "gzip"},
            {"name": "Transfer-Encoding", "value": "chunked"},
            {"name": "CONTENT-LENGTH", "value": "23"},
        ])
        original_headers = copy.deepcopy(event["params"]["responseHeaders"])
        cdp.handle_event(event)
        sent = websocket.sent[-1]
        self.assertEqual([message["method"] for message in websocket.sent], [
            "Fetch.getResponseBody", "Fetch.fulfillRequest",
        ])
        self.assertEqual(sent["params"]["responseCode"], 201)
        self.assertEqual(sent["params"]["responsePhrase"], "Created")
        self.assertEqual(sent["params"]["responseHeaders"][:-2], [
            header for header in original_headers
            if header["name"].lower() not in {"content-length", "content-encoding", "transfer-encoding"}
        ])
        self.assertEqual(sent["params"]["responseHeaders"][-2], {
            "name": "Content-Security-Policy", "value": "connect-src https://example.com",
        })
        self.assertEqual(sent["params"]["responseHeaders"][-1], {
            "name": "Content-Length", "value": str(len(body)),
        })
        self.assertEqual(base64.b64decode(sent["params"]["body"], validate=True), body)
        self.assertEqual(event["params"]["responseHeaders"], original_headers)
        self.assertEqual(evidence.events, [])
        self.assertNotIn("private-", repr(evidence.bundle()))

    def test_redirect_response_remains_unchanged_and_final_document_is_restricted(self) -> None:
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                cdp, websocket, evidence = _cdp()
                event = _response()
                event["params"]["responseStatusCode"] = status
                event["params"]["responseHeaders"].append({
                    "name": "Location", "value": "/next",
                })
                original = copy.deepcopy(event)
                cdp.handle_event(event)
                self.assertEqual(websocket.sent, [{
                    "id": 1, "method": "Fetch.continueResponse",
                    "params": {"requestId": "request-1"},
                }])
                self.assertEqual(event, original)
                # The next request is still checked, then the final response
                # must take the fresh-head body fulfillment path.
                next_request = _paused()
                next_request["params"]["request"]["url"] = "https://example.com/next"
                cdp.handle_event(next_request)
                self.assertEqual(websocket.sent[-1]["method"], "Fetch.continueRequest")
                cdp.handle_event(_response())
                self.assertEqual(websocket.sent[-1]["method"], "Fetch.fulfillRequest")
                self.assertFalse(any(item["kind"] == "telemetry_loss" for item in evidence.events))

    def test_nonredirect_3xx_without_location_cannot_skip_the_restriction(self) -> None:
        cdp, websocket, _ = _cdp()
        event = _response()
        event["params"]["responseStatusCode"] = 302
        cdp.handle_event(event)
        self.assertEqual([message["method"] for message in websocket.sent], [
            "Fetch.getResponseBody", "Fetch.fulfillRequest",
        ])

    def test_csp_uses_all_exact_authorized_origins_and_keeps_passive_https_fetch_possible(self) -> None:
        websocket = _FakeWebSocket()
        evidence = Evidence(max_events=100)
        request = make_probe_request(
            "https://example.com/",
            authorized_origins=["https://example.com", "https://assets.example.org:8443"],
        )
        cdp = CDP(websocket, evidence, request)
        cdp.handle_event(_response())
        policy = websocket.sent[-1]["params"]["responseHeaders"][-2]["value"]
        self.assertEqual(policy, "connect-src https://assets.example.org:8443 https://example.com")
        for forbidden in ("'self'", "ws:", "wss:", "*"):
            self.assertNotIn(forbidden, policy)
        cdp.handle_event(_paused("Fetch", "GET"))
        self.assertEqual(websocket.sent[-1]["method"], "Fetch.continueRequest")
        self.assertFalse(any(event["kind"] == "active_interaction" for event in evidence.events))

    def test_malformed_response_is_aborted_and_never_continued(self) -> None:
        malformed = [
            {"responseStatusCode": True},
            {"responseStatusCode": "200"},
            {"responseStatusCode": 99},
            {"responseStatusCode": 600},
            {"responseStatusText": "OK\r\nprivate"},
            {"responseStatusText": 42},
            {"responseHeaders": None},
            {"responseHeaders": [{"name": "bad\r\nname", "value": "x"}]},
            {"responseHeaders": [{"name": "x", "value": "bad\r\nvalue"}]},
            {"responseHeaders": [{"name": "x", "value": 1}]},
            {"responseHeaders": [{"name": "x", "value": "\ud800"}]},
            {"responseHeaders": [{"name": "x", "value": "x" * 16385}]},
            {"responseHeaders": [{"name": "x", "value": "y"}] * MAX_RESPONSE_HEADERS},
            {"responseHeaders": [{"name": "x", "value": "y"}] * (MAX_RESPONSE_HEADERS + 1)},
            {"responseHeaders": [{"name": "x", "value": "y" * 16384}] * (MAX_RESPONSE_HEADER_BYTES // 16384)},
            {"responseErrorReason": "Failed"},
            {"resourceType": "Image"},
            {"request": {"url": "https://unauthorized.example.org/", "method": "GET"}},
        ]
        for changes in malformed:
            with self.subTest(changes=list(changes)):
                cdp, websocket, evidence = _cdp()
                event = _response()
                event["params"].update(changes)
                with self.assertRaisesRegex(AgentError, "response restriction failed"):
                    cdp.handle_event(event)
                self.assertEqual([message["method"] for message in websocket.sent], ["Fetch.failRequest"])
                self.assertTrue(any(event["kind"] == "telemetry_loss" for event in evidence.events))

    def test_missing_response_status_cannot_be_mistaken_for_request_stage(self) -> None:
        cdp, websocket, evidence = _cdp()
        event = _response()
        del event["params"]["responseStatusCode"]
        with self.assertRaisesRegex(AgentError, "response restriction failed"):
            cdp.handle_event(event)
        self.assertEqual(websocket.sent[-1]["method"], "Fetch.failRequest")
        self.assertTrue(any(event["kind"] == "telemetry_loss" for event in evidence.events))

    def test_failed_body_or_fulfillment_command_aborts_and_marks_telemetry_loss(self) -> None:
        for failed_method in ("Fetch.getResponseBody", "Fetch.fulfillRequest"):
            with self.subTest(failed_method=failed_method):
                cdp, _websocket, evidence = _cdp()
                body_result = {"body": "eA==", "base64Encoded": True}
                responses = [AgentError("unsupported command"), {}]
                expected = ["Fetch.getResponseBody", "Fetch.failRequest"]
                if failed_method == "Fetch.fulfillRequest":
                    responses.insert(0, body_result)
                    expected.insert(1, "Fetch.fulfillRequest")
                with patch.object(cdp, "command", side_effect=responses) as command:
                    with self.assertRaisesRegex(AgentError, "response restriction failed"):
                        cdp.handle_event(_response())
                self.assertEqual([call.args[0] for call in command.call_args_list], expected)
                self.assertTrue(any(event["kind"] == "telemetry_loss" for event in evidence.events))

    def test_malformed_or_ambiguous_bodies_fail_closed_without_header_only_fallback(self) -> None:
        for body_result in (
            {},
            {"body": "eA=="},
            {"body": "eA==", "base64Encoded": 1},
            {"body": "text", "base64Encoded": False},
            {"body": 42, "base64Encoded": True},
            {"body": "private%%%", "base64Encoded": True},
            {"body": "\ud800", "base64Encoded": True},
            {"body": "eA==\n", "base64Encoded": True},
            {"body": "eB==", "base64Encoded": True},
            {"body": "", "base64Encoded": True},
            {"body": "eA==", "base64Encoded": True, "unexpected": "private"},
        ):
            with self.subTest(body_result=body_result):
                cdp, websocket, evidence = _cdp(results={"Fetch.getResponseBody": body_result})
                with self.assertRaisesRegex(AgentError, "response restriction failed"):
                    cdp.handle_event(_response())
                self.assertEqual([message["method"] for message in websocket.sent], [
                    "Fetch.getResponseBody", "Fetch.failRequest",
                ])
                self.assertTrue(any(event["kind"] == "telemetry_loss" for event in evidence.events))
                self.assertNotIn("private", repr(evidence.bundle()))

    def test_document_body_accepts_exact_budget_but_rejects_one_extra_byte(self) -> None:
        for size, accepted in ((MAX_DOCUMENT_BODY_BYTES, True), (MAX_DOCUMENT_BODY_BYTES + 1, False)):
            with self.subTest(size=size):
                encoded = base64.b64encode(b"x" * size).decode("ascii")
                cdp, websocket, _ = _cdp(results={
                    "Fetch.getResponseBody": {"body": encoded, "base64Encoded": True},
                })
                if accepted:
                    cdp.handle_event(_response())
                    sent = websocket.sent[-1]
                    self.assertEqual(sent["method"], "Fetch.fulfillRequest")
                    self.assertLess(len(json.dumps(sent).encode("utf-8")), MAX_WS_MESSAGE)
                else:
                    with self.assertRaisesRegex(AgentError, "response restriction failed"):
                        cdp.handle_event(_response())
                    self.assertEqual(websocket.sent[-1]["method"], "Fetch.failRequest")

    def test_body_limit_also_respects_the_requested_network_budget(self) -> None:
        for body in (b"x" * 7, b"x" * 8):
            with self.subTest(size=len(body)):
                cdp, websocket, _ = _cdp(results={
                    "Fetch.getResponseBody": {
                        "body": base64.b64encode(body).decode("ascii"), "base64Encoded": True,
                    },
                })
                cdp.request["budgets"]["max_network_bytes"] = 7
                if len(body) == 7:
                    cdp.handle_event(_response())
                    self.assertEqual(websocket.sent[-1]["method"], "Fetch.fulfillRequest")
                else:
                    with self.assertRaisesRegex(AgentError, "response restriction failed"):
                        cdp.handle_event(_response())
                    self.assertEqual(websocket.sent[-1]["method"], "Fetch.failRequest")

    def test_native_created_channels_record_attempt_even_if_no_csp_issue_was_emitted(self) -> None:
        for method in ("Network.webSocketCreated", "Network.webTransportCreated"):
            with self.subTest(method=method):
                cdp, websocket, evidence = _cdp()
                cdp.handle_event({"method": method, "params": {
                    "url": "wss://example.com/private-path?private-query=1",
                    "initiator": {"stack": "private-stack"},
                }})
                self.assertEqual(evidence.events, [{
                    "sequence": 0, "source": "cdp", "kind": "active_interaction",
                    "origin": None, "disposition": "attempted",
                }])
                self.assertEqual(websocket.sent, [])
                self.assertNotIn("private", repr(evidence.bundle()))

    def test_enforced_native_ws_and_wss_violations_record_attempt_without_url_text(self) -> None:
        for scheme in ("ws", "wss"):
            with self.subTest(scheme=scheme):
                cdp, websocket, evidence = _cdp()
                cdp.handle_event(_csp_issue(blockedURL=f"{scheme}://example.com/private-path?private-query=1"))
                self.assertEqual(websocket.sent, [])
                self.assertEqual(evidence.events, [{
                    "sequence": 0,
                    "source": "cdp",
                    "kind": "active_interaction",
                    "origin": None,
                    "disposition": "attempted",
                }])
                self.assertNotIn("private-path", repr(evidence.bundle()))
                self.assertNotIn("private-query", repr(evidence.bundle()))

    def test_http_connection_violation_retains_only_canonical_blocked_origin(self) -> None:
        cdp, _websocket, evidence = _cdp()
        cdp.handle_event(_csp_issue(blockedURL="https://OTHER.example.org:443/private-path?private-query=1"))
        self.assertEqual(evidence.events, [{
            "sequence": 0,
            "source": "cdp",
            "kind": "network_request",
            "origin": "https://other.example.org",
            "disposition": "blocked",
        }])

    def test_native_directive_text_is_classified_by_its_exact_directive_name(self) -> None:
        cdp, _websocket, evidence = _cdp()
        cdp.handle_event(_csp_issue(violatedDirective="connect-src https://example.com"))
        self.assertEqual([event["kind"] for event in evidence.events], ["active_interaction"])

    def test_report_only_and_other_directives_do_not_become_active_attempts(self) -> None:
        for overrides in (
            {"isReportOnly": True},
            {"violatedDirective": "script-src"},
            {"violatedDirective": "default-src"},
            {"violatedDirective": "connect-src-future"},
        ):
            with self.subTest(overrides=overrides):
                cdp, websocket, evidence = _cdp()
                cdp.handle_event(_csp_issue(**overrides))
                self.assertEqual(evidence.events, [])
                self.assertEqual(websocket.sent, [])

    def test_malformed_native_connection_audit_fails_closed(self) -> None:
        for overrides in (
            {"isReportOnly": "false"},
            {"blockedURL": None},
            {"blockedURL": "wss://[invalid"},
            {"blockedURL": "wss://example.com/" + "x" * 4096},
            {"contentSecurityPolicyViolationType": "kInlineViolation"},
        ):
            with self.subTest(overrides=list(overrides)):
                cdp, _websocket, evidence = _cdp()
                with self.assertRaises(AgentError):
                    cdp.handle_event(_csp_issue(**overrides))
                self.assertTrue(any(event["kind"] == "telemetry_loss" for event in evidence.events))


class BrowserTerminationBoundaryTests(unittest.TestCase):
    def test_interception_stays_attached_until_confirmed_termination(self) -> None:
        events = []
        process = Mock(pid=12345)
        websocket = Mock()
        process.wait.side_effect = lambda **_kwargs: events.append("exited")
        websocket.close.side_effect = lambda: events.append("detached")
        with patch("guest.browser_agent.os.killpg", side_effect=lambda *_args: events.append("killed")) as kill:
            _stop_browser(process, websocket)
        kill.assert_called_once_with(12345, signal.SIGKILL)
        self.assertEqual(events, ["killed", "exited", "detached"])

    def test_unconfirmed_termination_retains_interception_and_process(self) -> None:
        process = Mock(pid=12345)
        process.wait.side_effect = subprocess.TimeoutExpired("chromium", 1)
        websocket = Mock()
        with patch.object(_browser_agent, "_termination_guards", []) as guards:
            with patch("guest.browser_agent.os.killpg"), self.assertRaisesRegex(AgentError, "not confirmed"):
                _stop_browser(process, websocket)
            self.assertEqual(len(guards), 1)
            self.assertIs(guards[0][0], process)
            self.assertIs(guards[0][1], websocket)
        websocket.close.assert_not_called()

    def test_kill_failure_retains_guard_even_before_devtools_startup(self) -> None:
        for websocket in (None, Mock()):
            with self.subTest(devtools_started=websocket is not None):
                process = Mock(pid=12345)
                with patch.object(_browser_agent, "_termination_guards", []) as guards:
                    with (
                        patch("guest.browser_agent.os.killpg", side_effect=PermissionError("private failure")),
                        self.assertRaisesRegex(AgentError, "not confirmed"),
                    ):
                        _stop_browser(process, websocket)
                    self.assertEqual(len(guards), 1)
                    self.assertIs(guards[0][0], process)
                    self.assertIs(guards[0][1], websocket)
                process.wait.assert_not_called()
                if websocket is not None:
                    websocket.close.assert_not_called()

    def test_main_flushes_bounded_failure_before_holding_and_holds_if_write_fails(self) -> None:
        for write_fails in (False, True):
            with self.subTest(write_fails=write_fails):
                events = []
                messages = []
                process = Mock(pid=12345)
                websocket = Mock()
                channel = Mock()
                connection = Mock()
                connection.makefile.return_value = channel
                listener = Mock()
                listener.accept.return_value = (connection, None)
                wrapper = {
                    "runtime": {"nonce": "test-job-nonce"},
                    "probe_request": make_probe_request("https://example.com/"),
                }

                def write(line: bytes) -> None:
                    message = json.loads(line)
                    messages.append(message)
                    events.append("write-" + message["type"])
                    if write_fails and message["type"] == "result":
                        raise BrokenPipeError("private channel failure")

                channel.write.side_effect = write
                channel.flush.side_effect = lambda: events.append("flush")

                def failed_probe(*_args: Any) -> None:
                    _stop_browser(process, websocket)

                def hold() -> None:
                    self.assertIs(_browser_agent._termination_guards[0][0], process)
                    self.assertIs(_browser_agent._termination_guards[0][1], websocket)
                    events.append("host-termination-hold")

                with (
                    patch.object(_browser_agent, "_termination_guards", []),
                    patch.object(_browser_agent, "_hold_for_host_termination", side_effect=hold),
                    patch.object(_browser_agent, "_disable_collector_dumpability"),
                    patch.object(_browser_agent, "_run_probe", side_effect=failed_probe),
                    patch.object(_browser_agent, "_read_json_line", return_value={"type": "run", "nonce": "test-job-nonce"}),
                    patch.object(_browser_agent.socket, "socket", return_value=listener),
                    patch.object(_browser_agent.os, "killpg", side_effect=PermissionError("private kill failure")),
                    patch.object(_browser_agent.Path, "read_text", return_value=json.dumps(wrapper)),
                    patch.object(_browser_agent.sys, "argv", ["browser_agent.py", "/job/request.json"]),
                ):
                    self.assertEqual(_browser_agent.main(), 125 if write_fails else 1)
                self.assertEqual(events, [
                    "write-hello", "flush", "write-result",
                    *([] if write_fails else ["flush"]),
                    "host-termination-hold",
                ])
                self.assertEqual(messages[-1]["error"], "guest_probe_failed")
                self.assertEqual(messages[-1]["failure_code"], "agent_error")
                self.assertNotIn("private", repr(messages))
                websocket.close.assert_not_called()

    def test_no_termination_guard_requires_no_host_hold(self) -> None:
        with (
            patch.object(_browser_agent, "_termination_guards", []),
            patch.object(_browser_agent.time, "sleep") as sleep,
        ):
            _browser_agent._hold_for_host_termination()
        sleep.assert_not_called()

    def test_real_guard_stays_alive_after_catchable_interruption_until_external_kill(self) -> None:
        code = f"""
import sys
sys.path.insert(0, {str(PROJECT_DIR)!r})
from mote import browser_contract
sys.modules['browser_contract'] = browser_contract
from guest import browser_agent
browser_agent._termination_guards.append((object(), None))
real_sleep = browser_agent.time.sleep
interrupted = False
def interrupt_once(_seconds):
    global interrupted
    if not interrupted:
        interrupted = True
        print('interrupted', flush=True)
        raise KeyboardInterrupt
    print('holding', flush=True)
    real_sleep(10)
browser_agent.time.sleep = interrupt_once
browser_agent._hold_for_host_termination()
print('unsafe-return', flush=True)
"""
        process = subprocess.Popen(
            [sys.executable, "-B", "-c", code],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            with self.assertRaises(subprocess.TimeoutExpired):
                process.communicate(timeout=1)
        finally:
            process.kill()
            stdout, stderr = process.communicate(timeout=5)
        self.assertEqual(stdout, "interrupted\nholding\n")
        self.assertEqual(stderr, "")

    def test_already_exited_browser_still_reaps_and_closes(self) -> None:
        process = Mock(pid=12345)
        websocket = Mock()
        with patch("guest.browser_agent.os.killpg", side_effect=ProcessLookupError):
            _stop_browser(process, websocket)
        process.wait.assert_called_once_with(timeout=1)
        websocket.close.assert_called_once()


class PassiveResourceBoundaryTests(unittest.TestCase):
    def test_failure_code_does_not_echo_untrusted_error_text(self) -> None:
        self.assertEqual(_failure_code(AgentError("url and page text")), "agent_error")
        self.assertEqual(_failure_code(ProbeFailure("navigation_no_loader")), "navigation_no_loader")

    def test_authorized_document_get_is_the_explicit_passive_case(self) -> None:
        cdp, websocket, evidence = _cdp()

        cdp.handle_event(_paused("Document", "GET"))

        self.assertEqual(websocket.sent[-1]["method"], "Fetch.continueRequest")
        self.assertEqual(websocket.sent[-1]["params"], {"requestId": "request-1"})
        self.assertIn(
            {
                "sequence": 0,
                "source": "cdp",
                "kind": "network_request",
                "origin": "https://example.com",
                "disposition": "allowed",
            },
            evidence.events,
        )

    def test_get_does_not_authorize_bidirectional_or_unknown_resource_types(self) -> None:
        blocked_types: tuple[Any, ...] = (
            "WebSocket",
            "EventSource",
            "Ping",
            "Other",
            "CSPViolationReport",
            "Preflight",
            "WebTransport",
            "FutureBidirectionalType",
            "",
            None,
            7,
        )
        for resource_type in blocked_types:
            with self.subTest(resource_type=resource_type):
                cdp, websocket, evidence = _cdp()

                cdp.handle_event(_paused(resource_type, "GET"))

                self.assertEqual(websocket.sent[-1]["method"], "Fetch.failRequest")
                self.assertEqual(
                    websocket.sent[-1]["params"],
                    {"requestId": "request-1", "errorReason": "BlockedByClient"},
                )
                self.assertTrue(
                    any(event["kind"] == "active_interaction" for event in evidence.events)
                )
                self.assertTrue(
                    any(
                        event["kind"] == "network_request"
                        and event["disposition"] == "blocked"
                        for event in evidence.events
                    )
                )

    def test_only_exact_authorized_favicon_get_is_passive_other(self) -> None:
        for url, method, expected in (
            ("https://example.com/favicon.ico", "GET", "Fetch.continueRequest"),
            ("https://example.com/favicon.ico?x=1", "GET", "Fetch.failRequest"),
            ("https://example.com/favicon.ico", "POST", "Fetch.failRequest"),
            ("https://elsewhere.example/favicon.ico", "GET", "Fetch.failRequest"),
            ("https://example.com/other.ico", "GET", "Fetch.failRequest"),
        ):
            with self.subTest(url=url, method=method):
                cdp, websocket, evidence = _cdp()
                paused = _paused("Other", method)
                paused["params"]["request"]["url"] = url
                cdp.handle_event(paused)
                self.assertEqual(websocket.sent[-1]["method"], expected)
                if expected == "Fetch.continueRequest":
                    self.assertFalse(
                        any(event["kind"] == "active_interaction" for event in evidence.events)
                    )


class AutoAttachBoundaryTests(unittest.TestCase):
    def test_auto_attach_is_exact_and_installed_in_setup_before_discovery(self) -> None:
        commands = [method for method, _ in CDP_SETUP_COMMANDS]
        index = commands.index("Target.setAutoAttach")
        self.assertLess(index, commands.index("Target.setDiscoverTargets"))
        self.assertLess(index, commands.index("Fetch.enable"))
        self.assertEqual(
            CDP_SETUP_COMMANDS[index][1],
            {
                "autoAttach": True,
                "waitForDebuggerOnStart": True,
                "flatten": True,
                "filter": [{"type": "browser", "exclude": True}, {}],
            },
        )
        self.assertNotIn("Page.navigate", commands)

    def test_window_open_attempt_is_evidence_even_when_no_target_is_created(self) -> None:
        cdp, websocket, evidence = _cdp()

        cdp.handle_event(
            {
                "method": "Page.windowOpen",
                "params": {
                    "url": "https://example.com/popup",
                    "windowName": "child",
                    "windowFeatures": [],
                    "userGesture": False,
                },
            }
        )

        self.assertEqual(websocket.sent, [])
        self.assertIn(
            {
                "sequence": 0,
                "source": "cdp",
                "kind": "popup_attempt",
                "origin": None,
                "disposition": "attempted",
            },
            evidence.events,
        )

    def test_every_attached_child_type_is_closed_without_resume(self) -> None:
        for target_type in ("page", "tab", "iframe", "worker", "service_worker"):
            with self.subTest(target_type=target_type):
                cdp, websocket, evidence = _cdp(
                    results={"Target.closeTarget": {"success": True}}
                )

                cdp.handle_event(
                    {
                        "method": "Target.attachedToTarget",
                        "params": {
                            "sessionId": f"session-{target_type}",
                            "waitingForDebugger": True,
                            "targetInfo": {
                                "targetId": f"target-{target_type}",
                                "type": target_type,
                            },
                        },
                    }
                )

                self.assertEqual(
                    websocket.sent,
                    [
                        {
                            "id": 1,
                            "method": "Target.closeTarget",
                            "params": {"targetId": f"target-{target_type}"},
                        }
                    ],
                )
                self.assertFalse(
                    any(
                        message["method"] == "Runtime.runIfWaitingForDebugger"
                        for message in websocket.sent
                    )
                )
                expected_kind = (
                    "popup_attempt" if target_type in {"page", "tab"} else "active_interaction"
                )
                self.assertTrue(any(event["kind"] == expected_kind for event in evidence.events))

    def test_failed_child_close_fails_the_probe_and_marks_telemetry_loss(self) -> None:
        cdp, websocket, evidence = _cdp(
            results={"Target.closeTarget": {"success": False}}
        )

        with self.assertRaisesRegex(AgentError, "could not be closed"):
            cdp.handle_event(
                {
                    "method": "Target.attachedToTarget",
                    "params": {
                        "sessionId": "child-session",
                        "waitingForDebugger": True,
                        "targetInfo": {"targetId": "child-target", "type": "worker"},
                    },
                }
            )

        self.assertEqual([message["method"] for message in websocket.sent], ["Target.closeTarget"])
        self.assertTrue(any(event["kind"] == "telemetry_loss" for event in evidence.events))

    def test_unpaused_child_is_closed_then_fails_the_probe(self) -> None:
        cdp, websocket, evidence = _cdp(
            results={"Target.closeTarget": {"success": True}}
        )

        with self.assertRaisesRegex(AgentError, "not debugger-paused"):
            cdp.handle_event(
                {
                    "method": "Target.attachedToTarget",
                    "params": {
                        "sessionId": "child-session",
                        "waitingForDebugger": False,
                        "targetInfo": {"targetId": "child-target", "type": "iframe"},
                    },
                }
            )

        self.assertEqual([message["method"] for message in websocket.sent], ["Target.closeTarget"])
        self.assertTrue(any(event["kind"] == "telemetry_loss" for event in evidence.events))

    def test_malformed_attachment_fails_closed_without_resuming_it(self) -> None:
        cdp, websocket, evidence = _cdp()

        with self.assertRaisesRegex(AgentError, "metadata is malformed"):
            cdp.handle_event(
                {
                    "method": "Target.attachedToTarget",
                    "params": {
                        "sessionId": "child-session",
                        "waitingForDebugger": True,
                        "targetInfo": {"type": "worker"},
                    },
                }
            )

        self.assertEqual(websocket.sent, [])
        self.assertTrue(any(event["kind"] == "telemetry_loss" for event in evidence.events))


if __name__ == "__main__":
    unittest.main()
