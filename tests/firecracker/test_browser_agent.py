from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path
from typing import Any


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


class PassiveResourceBoundaryTests(unittest.TestCase):
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
