from __future__ import annotations

import copy
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

from guest.browser_agent import (  # noqa: E402
    CDP,
    CDP_SETUP_COMMANDS,
    AgentError,
    Evidence,
    MAX_RESPONSE_HEADER_BYTES,
    MAX_RESPONSE_HEADERS,
    ProbeFailure,
    _failure_code,
    _stop_browser,
)
from mote.browser_contract import make_probe_request  # noqa: E402


class _FakeWebSocket:
    def __init__(self, results: dict[str, dict[str, Any]] | None = None) -> None:
        self.results = results or {}
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
    def test_native_audits_and_document_response_interception_are_installed_before_navigation(self) -> None:
        commands = [method for method, _ in CDP_SETUP_COMMANDS]
        self.assertLess(commands.index("Audits.enable"), commands.index("Fetch.enable"))
        fetch = dict(CDP_SETUP_COMMANDS)["Fetch.enable"]
        self.assertIn(
            {"urlPattern": "*", "resourceType": "Document", "requestStage": "Response"},
            fetch["patterns"],
        )
        self.assertNotIn("Page.navigate", commands)

    def test_document_csp_is_added_without_replacing_original_headers_status_or_body(self) -> None:
        cdp, websocket, evidence = _cdp()
        event = _response()
        event["params"].update({"responseStatusCode": 302, "responseStatusText": "Found"})
        original_csp = {"name": "Content-Security-Policy", "value": "script-src 'self'; connect-src 'none'"}
        event["params"]["responseHeaders"].extend([
            original_csp,
            {"name": "set-cookie", "value": "private-cookie=private-value; Secure"},
            {"name": "location", "value": "https://example.com/next"},
        ])
        original_headers = copy.deepcopy(event["params"]["responseHeaders"])
        cdp.handle_event(event)
        sent = websocket.sent[-1]
        self.assertEqual(sent["method"], "Fetch.continueResponse")
        self.assertEqual(sent["params"]["responseCode"], 302)
        self.assertEqual(sent["params"]["responsePhrase"], "Found")
        self.assertEqual(sent["params"]["responseHeaders"][:-1], original_headers)
        self.assertEqual(sent["params"]["responseHeaders"][-1], {
            "name": "Content-Security-Policy", "value": "connect-src https://example.com",
        })
        self.assertNotIn("body", sent["params"])
        self.assertEqual(event["params"]["responseHeaders"], original_headers)
        self.assertEqual(evidence.events, [])

    def test_csp_uses_all_exact_authorized_origins_and_keeps_passive_https_fetch_possible(self) -> None:
        websocket = _FakeWebSocket()
        evidence = Evidence(max_events=100)
        request = make_probe_request(
            "https://example.com/",
            authorized_origins=["https://example.com", "https://assets.example.org:8443"],
        )
        cdp = CDP(websocket, evidence, request)
        cdp.handle_event(_response())
        policy = websocket.sent[-1]["params"]["responseHeaders"][-1]["value"]
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

    def test_failed_csp_command_aborts_and_marks_telemetry_loss(self) -> None:
        cdp, _websocket, evidence = _cdp()
        with patch.object(cdp, "command", side_effect=[AgentError("unsupported command"), {}]) as command:
            with self.assertRaisesRegex(AgentError, "response restriction failed"):
                cdp.handle_event(_response())
        self.assertEqual([call.args[0] for call in command.call_args_list], [
            "Fetch.continueResponse", "Fetch.failRequest",
        ])
        self.assertTrue(any(event["kind"] == "telemetry_loss" for event in evidence.events))

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

    def test_unconfirmed_termination_is_an_error(self) -> None:
        process = Mock(pid=12345)
        process.wait.side_effect = subprocess.TimeoutExpired("chromium", 1)
        websocket = Mock()
        with patch("guest.browser_agent.os.killpg"), self.assertRaisesRegex(AgentError, "not confirmed"):
            _stop_browser(process, websocket)
        websocket.close.assert_called_once()

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
