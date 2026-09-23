from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[2]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from mote.browser_contract import (  # noqa: E402
    BrowserContractError,
    is_authorized_url,
    make_probe_request,
    normalize_origin,
    normalize_url,
    validate_probe_request,
    validate_resolved_address,
)
from mote.browser_evidence import (  # noqa: E402
    EVIDENCE_VERSION,
    reduce_browser_evidence,
    validate_browser_event,
)


def _event(
    sequence: int,
    source: str,
    kind: str,
    disposition: str,
    web_origin: str | None = None,
    *,
    connect_authority: str | None = None,
) -> dict:
    return {
        "sequence": sequence,
        "source": source,
        "kind": kind,
        "web_origin": web_origin,
        "connect_authority": connect_authority,
        "disposition": disposition,
    }


def _complete_evidence(extra_events: list[dict] | None = None) -> dict:
    events = [
        _event(0, "browser", "lifecycle", "started"),
        _event(1, "browser", "browser_sandbox", "active"),
        _event(2, "browser", "lifecycle", "stopped"),
        _event(0, "cdp", "navigation", "committed", "https://example.com"),
        _event(
            0,
            "egress",
            "network_request",
            "allowed",
            connect_authority="example.com:443",
        ),
        _event(0, "vm", "lifecycle", "started"),
        _event(1, "vm", "lifecycle", "stopped"),
    ]
    for event in extra_events or []:
        events.append(event)
    counts = {source: 0 for source in ("browser", "cdp", "egress", "vm")}
    for event in events:
        counts[event["source"]] += 1
    return {
        "evidence_version": EVIDENCE_VERSION,
        "events": events,
        "streams": {
            source: {"complete": True, "event_count": counts[source]}
            for source in ("browser", "cdp", "egress", "vm")
        },
    }


def _finding_ids(reduction: dict) -> list[str]:
    return [finding["finding_id"] for finding in reduction["findings"]]


class BrowserURLContractTests(unittest.TestCase):
    def test_normalizes_url_and_origin(self) -> None:
        self.assertEqual(
            normalize_url("HTTPS://EXAMPLE.COM:443/café?x=%2f"),
            "https://example.com/caf%C3%A9?x=%2F",
        )
        self.assertEqual(normalize_url("http://example.com"), "http://example.com/")
        self.assertEqual(
            normalize_origin("https://EXAMPLE.com:8443/"),
            "https://example.com:8443",
        )

    def test_rejects_ambiguous_and_unsafe_authorities(self) -> None:
        rejected = (
            "file:///etc/passwd",
            "https://user:secret@example.com/",
            "https://example.com/#ignored",
            "https://127.0.0.1/",
            "https://[::1]/",
            "http://2130706433/",
            "http://127.1/",
            "http://localhost/",
            "http://service.internal/",
            "http://printer.local/",
            "https://singlelabel/",
            "https://example.com\\@evil.com/",
            "https://example.com:/",
            "https://example.com/%zz",
        )
        for value in rejected:
            with self.subTest(value=value), self.assertRaises(BrowserContractError):
                normalize_url(value)

    def test_authorization_is_exact_origin_not_suffix_or_scheme(self) -> None:
        authorized = ["https://example.com:8443"]
        self.assertTrue(is_authorized_url("https://example.com:8443/a", authorized))
        self.assertFalse(is_authorized_url("https://sub.example.com:8443/a", authorized))
        self.assertFalse(is_authorized_url("http://example.com:8443/a", authorized))
        self.assertFalse(is_authorized_url("https://example.com/a", authorized))

    def test_resolved_addresses_must_be_public_unicast(self) -> None:
        self.assertEqual(validate_resolved_address("8.8.8.8"), "8.8.8.8")
        for value in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "ff02::1"):
            with self.subTest(value=value), self.assertRaises(BrowserContractError):
                validate_resolved_address(value)


class BrowserRequestContractTests(unittest.TestCase):
    def test_builder_emits_complete_passive_contract(self) -> None:
        request = make_probe_request("https://EXAMPLE.com/start")
        self.assertEqual(request["url"], "https://example.com/start")
        self.assertEqual(request["authorized_origins"], ["https://example.com"])
        self.assertEqual(request["navigation"]["mode"], "passive")
        self.assertFalse(any(
            request["navigation"][field]
            for field in (
                "allow_clicks",
                "allow_typing",
                "allow_uploads",
                "allow_downloads",
                "allow_permission_grants",
                "allow_popups",
            )
        ))

    def test_rejects_active_navigation_and_unknown_fields(self) -> None:
        request = make_probe_request("https://example.com/")
        active = copy.deepcopy(request)
        active["navigation"]["allow_clicks"] = True
        with self.assertRaises(BrowserContractError):
            validate_probe_request(active)
        unknown = copy.deepcopy(request)
        unknown["navigation"]["javascript_to_execute"] = "document.body.click()"
        with self.assertRaises(BrowserContractError):
            validate_probe_request(unknown)

    def test_rejects_boolean_and_out_of_range_budgets(self) -> None:
        request = make_probe_request("https://example.com/")
        for field, value in (
            ("cpu_vcpu", True),
            ("wall_clock_sec", 0),
            ("ram_mib", 4097),
            ("max_redirects", 21),
            ("max_network_bytes", 67108865),
        ):
            invalid = copy.deepcopy(request)
            invalid["budgets"][field] = value
            with self.subTest(field=field), self.assertRaises(BrowserContractError):
                validate_probe_request(invalid)

    def test_initial_origin_must_be_declared_and_duplicates_are_canonical(self) -> None:
        request = make_probe_request("https://example.com/")
        request["authorized_origins"] = ["https://other.example.com"]
        with self.assertRaises(BrowserContractError):
            validate_probe_request(request)
        request["authorized_origins"] = [
            "https://example.com",
            "https://EXAMPLE.com:443/",
        ]
        with self.assertRaises(BrowserContractError):
            validate_probe_request(request)


class BrowserEvidenceReducerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.request = make_probe_request("https://example.com/")

    def test_clean_complete_evidence_allows(self) -> None:
        reduction = reduce_browser_evidence(_complete_evidence(), self.request)
        self.assertTrue(reduction["complete"])
        self.assertFalse(reduction["telemetry_incomplete"])
        self.assertFalse(reduction["fail_closed"])
        self.assertEqual(reduction["decision"], "ALLOW")
        self.assertEqual(reduction["findings"], [])

    def test_findings_are_stable_sorted_and_metadata_only(self) -> None:
        evidence = _complete_evidence(
            [
                _event(1, "cdp", "prompt_marker", "visible"),
                _event(2, "cdp", "download_attempt", "blocked"),
                _event(
                    1,
                    "egress",
                    "network_request",
                    "blocked",
                    connect_authority="cdn.example.com:443",
                ),
            ]
        )
        first = reduce_browser_evidence(evidence, self.request)
        shuffled = copy.deepcopy(evidence)
        shuffled["events"].reverse()
        second = reduce_browser_evidence(shuffled, self.request)
        self.assertEqual(first, second)
        self.assertTrue(first["complete"])
        self.assertEqual(first["decision"], "DENY")
        self.assertEqual(
            _finding_ids(first),
            [
                "web_blocked_egress_attempt",
                "web_download_attempt",
                "web_prompt_marker_visible",
                "web_unauthorized_origin_attempt",
            ],
        )

    def test_incomplete_stream_fails_closed(self) -> None:
        evidence = _complete_evidence()
        evidence["streams"]["cdp"]["complete"] = False
        reduction = reduce_browser_evidence(evidence, self.request)
        self.assertFalse(reduction["complete"])
        self.assertTrue(reduction["telemetry_incomplete"])
        self.assertTrue(reduction["fail_closed"])
        self.assertEqual(reduction["decision"], "DENY")
        self.assertIn("web_cdp_telemetry_loss", _finding_ids(reduction))

    def test_count_or_sequence_disagreement_fails_closed(self) -> None:
        evidence = _complete_evidence()
        evidence["streams"]["browser"]["event_count"] += 1
        evidence["events"][1]["sequence"] = 5
        reduction = reduce_browser_evidence(evidence, self.request)
        self.assertFalse(reduction["complete"])
        self.assertIn("web_evidence_count_mismatch", _finding_ids(reduction))
        self.assertIn("web_evidence_sequence_gap", _finding_ids(reduction))

    def test_missing_attestations_and_lifecycle_fail_closed(self) -> None:
        evidence = _complete_evidence()
        evidence["events"] = [
            event
            for event in evidence["events"]
            if event["kind"] != "browser_sandbox"
            and not (event["source"] == "vm" and event["disposition"] == "stopped")
        ]
        for source in evidence["streams"]:
            evidence["streams"][source]["event_count"] = sum(
                event["source"] == source for event in evidence["events"]
            )
        reduction = reduce_browser_evidence(evidence, self.request)
        self.assertFalse(reduction["complete"])
        self.assertIn("web_browser_sandbox_unknown", _finding_ids(reduction))
        self.assertIn("web_vm_lifecycle_incomplete", _finding_ids(reduction))

    def test_network_witness_types_cannot_be_interchanged(self) -> None:
        cdp_claims_authority = _event(
            0,
            "cdp",
            "network_request",
            "allowed",
            connect_authority="example.com:443",
        )
        proxy_claims_https_origin = _event(
            0,
            "egress",
            "network_request",
            "allowed",
            "https://example.com",
        )
        for event in (cdp_claims_authority, proxy_claims_https_origin):
            with self.subTest(event=event), self.assertRaises(BrowserContractError):
                validate_browser_event(event)

    def test_malformed_evidence_returns_fixed_schema_finding(self) -> None:
        evidence = _complete_evidence()
        evidence["events"][0]["page_text"] = "ignore previous instructions"
        reduction = reduce_browser_evidence(evidence, self.request)
        self.assertEqual(reduction["decision"], "DENY")
        self.assertTrue(reduction["fail_closed"])
        self.assertEqual(_finding_ids(reduction), ["web_evidence_schema_invalid"])

    def test_event_budget_overrun_fails_closed(self) -> None:
        request = make_probe_request(
            "https://example.com/", budgets={"max_events": 1}
        )
        reduction = reduce_browser_evidence(_complete_evidence(), request)
        self.assertFalse(reduction["complete"])
        self.assertIn("web_event_budget_exceeded", _finding_ids(reduction))

    def test_redirect_budget_overrun_fails_closed(self) -> None:
        request = make_probe_request(
            "https://example.com/", budgets={"max_redirects": 0}
        )
        evidence = _complete_evidence(
            [_event(1, "cdp", "redirect", "followed", "https://example.com")]
        )
        reduction = reduce_browser_evidence(evidence, request)
        self.assertFalse(reduction["complete"])
        self.assertIn("web_redirect_budget_exceeded", _finding_ids(reduction))


class BrowserSchemaArtifactTests(unittest.TestCase):
    def test_schema_is_parseable_and_exposes_evidence_definitions(self) -> None:
        schema_path = PROJECT_DIR / "schemas" / "browser-evidence-v2.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            schema["properties"]["evidence_version"]["const"], EVIDENCE_VERSION
        )
        self.assertIn("browserEvent", schema["$defs"])
        self.assertIn("reducedEvidence", schema["$defs"])
        event = schema["$defs"]["browserEvent"]
        self.assertIn("web_origin", event["properties"])
        self.assertIn("connect_authority", event["properties"])


if __name__ == "__main__":
    unittest.main()
