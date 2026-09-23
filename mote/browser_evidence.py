"""Host-owned browser evidence v2 with explicit network witness types.

The guest/rootfs contract remains ``cindermote.browser-evidence/v1`` and is
validated by :mod:`browser_contract`.  The host translates only guest-owned
browser/CDP events into this v2 schema, then adds independently collected
proxy and VM evidence.  HTTPS CONNECT authorities are transport evidence and
are never represented as web origins.
"""

from __future__ import annotations

from collections import Counter
from typing import Any
from urllib.parse import urlsplit

try:
    from .browser_contract import (
        FINDING_SEVERITIES,
        MAX_EVIDENCE_EVENTS,
        REQUIRED_STREAMS,
        TELEMETRY_INCOMPLETE_FINDINGS as V1_TELEMETRY_INCOMPLETE_FINDINGS,
        BrowserContractError,
        normalize_origin,
        validate_probe_request,
    )
except ImportError:  # Direct execution from the mote directory.
    from browser_contract import (  # type: ignore
        FINDING_SEVERITIES,
        MAX_EVIDENCE_EVENTS,
        REQUIRED_STREAMS,
        TELEMETRY_INCOMPLETE_FINDINGS as V1_TELEMETRY_INCOMPLETE_FINDINGS,
        BrowserContractError,
        normalize_origin,
        validate_probe_request,
    )


EVIDENCE_VERSION = "cindermote.browser-evidence/v2"

EVIDENCE_KEYS = {"evidence_version", "events", "streams"}
STREAM_STATUS_KEYS = {"complete", "event_count"}
EVENT_KEYS = {
    "sequence",
    "source",
    "kind",
    "web_origin",
    "connect_authority",
    "disposition",
}

_KIND_DISPOSITIONS = {
    "lifecycle": {"started", "stopped", "failed"},
    "navigation": {"committed", "blocked", "failed"},
    "redirect": {"followed", "blocked"},
    "network_request": {"allowed", "blocked"},
    "download_attempt": {"attempted", "blocked"},
    "file_upload_attempt": {"attempted", "blocked"},
    "popup_attempt": {"attempted", "blocked"},
    "active_interaction": {"attempted", "blocked"},
    "prompt_marker": {"visible", "hidden"},
    "mixed_content": {"observed", "blocked"},
    "browser_sandbox": {"active", "inactive"},
    "telemetry_loss": {"observed"},
}

_KIND_SOURCES = {
    "lifecycle": {"browser", "vm"},
    "navigation": {"cdp"},
    "redirect": {"cdp"},
    "network_request": {"cdp", "egress"},
    "download_attempt": {"cdp"},
    "file_upload_attempt": {"browser", "cdp"},
    "popup_attempt": {"cdp"},
    "active_interaction": {"browser", "cdp"},
    "prompt_marker": {"browser", "cdp"},
    "mixed_content": {"cdp"},
    "browser_sandbox": {"browser", "cdp"},
    "telemetry_loss": set(REQUIRED_STREAMS),
}

_WEB_ORIGIN_REQUIRED_KINDS = {"navigation", "redirect"}
_STREAM_LOSS_FINDING = {
    "browser": "web_browser_telemetry_loss",
    "cdp": "web_cdp_telemetry_loss",
    "egress": "web_egress_telemetry_loss",
    "vm": "web_vm_telemetry_loss",
}

# v2 no longer makes a host/guest destination-equality claim.  Completeness of
# the independent CDP and egress streams remains mandatory and fail-closed.
TELEMETRY_INCOMPLETE_FINDINGS = frozenset(
    set(V1_TELEMETRY_INCOMPLETE_FINDINGS)
    - {"web_host_guest_network_mismatch", "web_host_guest_network_unknown"}
)


def normalize_connect_authority(value: str) -> str:
    """Return canonical ``host:port`` for one HTTPS CONNECT authority."""

    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or value.count(":") != 1
        or any(character in value for character in "/?#@\\")
    ):
        raise BrowserContractError("CONNECT authority must be canonical host:port")
    raw_host, raw_port = value.rsplit(":", 1)
    if not raw_host or not raw_port.isdigit():
        raise BrowserContractError("CONNECT authority must include an explicit port")
    port = int(raw_port)
    if not 1 <= port <= 65535:
        raise BrowserContractError("CONNECT authority port is invalid")
    origin = normalize_origin(f"https://{raw_host}:{port}")
    hostname = urlsplit(origin).hostname
    if hostname is None:
        raise BrowserContractError("CONNECT authority hostname is invalid")
    return f"{hostname}:{port}"


def connect_authority_for_origin(value: str) -> str:
    """Map an authorized HTTPS web origin to its permitted CONNECT authority."""

    origin = normalize_origin(value)
    parsed = urlsplit(origin)
    if parsed.scheme != "https" or parsed.hostname is None:
        raise BrowserContractError("CONNECT authority requires an HTTPS origin")
    return f"{parsed.hostname}:{parsed.port or 443}"


def validate_browser_event(value: Any) -> dict[str, Any]:
    """Validate one v2 event and enforce source-owned witness semantics."""

    if not isinstance(value, dict) or set(value) != EVENT_KEYS:
        raise BrowserContractError("browser event has missing or extra fields")
    sequence = value["sequence"]
    if (
        not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or not 0 <= sequence < MAX_EVIDENCE_EVENTS
    ):
        raise BrowserContractError("browser event sequence is invalid")
    source = value["source"]
    if source not in REQUIRED_STREAMS:
        raise BrowserContractError("browser event source is invalid")
    kind = value["kind"]
    if kind not in _KIND_DISPOSITIONS or source not in _KIND_SOURCES[kind]:
        raise BrowserContractError("browser event source cannot emit this kind")
    disposition = value["disposition"]
    if disposition not in _KIND_DISPOSITIONS[kind]:
        raise BrowserContractError("browser event disposition is invalid")

    raw_origin = value["web_origin"]
    if raw_origin is None:
        web_origin = None
    elif isinstance(raw_origin, str):
        web_origin = normalize_origin(raw_origin)
    else:
        raise BrowserContractError("browser event web_origin is invalid")

    raw_authority = value["connect_authority"]
    if raw_authority is None:
        connect_authority = None
    elif isinstance(raw_authority, str):
        connect_authority = normalize_connect_authority(raw_authority)
    else:
        raise BrowserContractError("browser event connect_authority is invalid")

    if web_origin is not None and connect_authority is not None:
        raise BrowserContractError("browser event interchanges independent witnesses")
    if kind in _WEB_ORIGIN_REQUIRED_KINDS:
        if web_origin is None or connect_authority is not None:
            raise BrowserContractError("CDP event requires a web origin")
    elif kind == "network_request":
        if source == "cdp":
            if web_origin is None or connect_authority is not None:
                raise BrowserContractError("CDP network evidence requires a web origin")
        elif source == "egress":
            if (web_origin is None) == (connect_authority is None):
                raise BrowserContractError(
                    "proxy network evidence requires exactly one witness type"
                )
            if web_origin is not None and urlsplit(web_origin).scheme != "http":
                raise BrowserContractError(
                    "proxy web-origin evidence is limited to plain HTTP"
                )
    elif web_origin is not None or connect_authority is not None:
        raise BrowserContractError("browser event kind cannot carry a destination")

    return {
        "sequence": sequence,
        "source": source,
        "kind": kind,
        "web_origin": web_origin,
        "connect_authority": connect_authority,
        "disposition": disposition,
    }


def validate_browser_evidence(value: Any) -> dict[str, Any]:
    """Validate a host-owned v2 evidence bundle."""

    if not isinstance(value, dict) or set(value) != EVIDENCE_KEYS:
        raise BrowserContractError("browser evidence has missing or extra fields")
    if value["evidence_version"] != EVIDENCE_VERSION:
        raise BrowserContractError("unsupported browser evidence version")
    raw_events = value["events"]
    if not isinstance(raw_events, list) or len(raw_events) > MAX_EVIDENCE_EVENTS:
        raise BrowserContractError("browser evidence events must be a bounded list")
    events = [validate_browser_event(event) for event in raw_events]

    raw_streams = value["streams"]
    if not isinstance(raw_streams, dict) or set(raw_streams) != set(REQUIRED_STREAMS):
        raise BrowserContractError("browser evidence stream set is incomplete")
    streams: dict[str, dict[str, Any]] = {}
    for source in REQUIRED_STREAMS:
        status = raw_streams[source]
        if not isinstance(status, dict) or set(status) != STREAM_STATUS_KEYS:
            raise BrowserContractError("browser evidence stream status is malformed")
        complete = status["complete"]
        count = status["event_count"]
        if not isinstance(complete, bool):
            raise BrowserContractError("browser evidence stream complete must be bool")
        if (
            not isinstance(count, int)
            or isinstance(count, bool)
            or not 0 <= count <= MAX_EVIDENCE_EVENTS
        ):
            raise BrowserContractError("browser evidence stream event_count is invalid")
        streams[source] = {"complete": complete, "event_count": count}
    return {
        "evidence_version": EVIDENCE_VERSION,
        "events": events,
        "streams": streams,
    }


def _finding_items(counts: Counter[str]) -> list[dict[str, Any]]:
    return [
        {
            "finding_id": finding_id,
            "count": int(counts[finding_id]),
            "severity": FINDING_SEVERITIES[finding_id],
        }
        for finding_id in sorted(counts)
        if counts[finding_id] > 0
    ]


def _closed_reduction(finding_id: str) -> dict[str, Any]:
    counts: Counter[str] = Counter({finding_id: 1})
    return {
        "evidence_version": EVIDENCE_VERSION,
        "complete": False,
        "telemetry_incomplete": True,
        "fail_closed": True,
        "decision": "DENY",
        "events_observed": 0,
        "streams": {
            source: {
                "declared_event_count": 0,
                "observed_event_count": 0,
                "complete": False,
            }
            for source in REQUIRED_STREAMS
        },
        "findings": _finding_items(counts),
    }


def reduce_browser_evidence(evidence: Any, request: Any) -> dict[str, Any]:
    """Reduce independent v2 proxy/CDP witnesses without equating them."""

    try:
        normalized_request = validate_probe_request(request)
        normalized_evidence = validate_browser_evidence(evidence)
    except Exception:
        return _closed_reduction("web_evidence_schema_invalid")

    events = normalized_evidence["events"]
    streams = normalized_evidence["streams"]
    allowed_origins = set(normalized_request["authorized_origins"])
    allowed_authorities = {
        connect_authority_for_origin(origin)
        for origin in allowed_origins
        if urlsplit(origin).scheme == "https"
    }
    findings: Counter[str] = Counter()
    incomplete = False
    source_events = {source: [] for source in REQUIRED_STREAMS}

    for event in events:
        source_events[event["source"]].append(event)
        kind = event["kind"]
        disposition = event["disposition"]
        web_origin = event["web_origin"]
        connect_authority = event["connect_authority"]

        if kind in _WEB_ORIGIN_REQUIRED_KINDS and web_origin not in allowed_origins:
            findings["web_unauthorized_origin_attempt"] += 1
        if kind == "network_request":
            if web_origin is not None and web_origin not in allowed_origins:
                findings["web_unauthorized_origin_attempt"] += 1
            if (
                connect_authority is not None
                and connect_authority not in allowed_authorities
            ):
                findings["web_unauthorized_origin_attempt"] += 1
            if disposition == "blocked":
                findings["web_blocked_egress_attempt"] += 1
        elif kind == "download_attempt":
            findings["web_download_attempt"] += 1
        elif kind == "file_upload_attempt":
            findings["web_file_upload_attempt"] += 1
        elif kind == "popup_attempt":
            findings["web_popup_attempt"] += 1
        elif kind == "active_interaction":
            findings["web_active_interaction_attempt"] += 1
        elif kind == "prompt_marker":
            findings[f"web_prompt_marker_{disposition}"] += 1
        elif kind == "mixed_content":
            findings["web_mixed_content_observed"] += 1
        elif kind == "browser_sandbox" and disposition == "inactive":
            findings["web_browser_sandbox_inactive"] += 1
        elif kind == "telemetry_loss":
            findings[_STREAM_LOSS_FINDING[event["source"]]] += 1
            incomplete = True
        elif kind == "lifecycle" and disposition == "failed":
            finding_id = (
                "web_browser_execution_failed"
                if event["source"] == "browser"
                else "web_vm_execution_failed"
            )
            findings[finding_id] += 1
            incomplete = True
        elif kind == "navigation" and disposition in {"blocked", "failed"}:
            findings["web_navigation_failed"] += 1
            incomplete = True

    stream_summary: dict[str, dict[str, Any]] = {}
    for source in REQUIRED_STREAMS:
        observed = source_events[source]
        declared_count = streams[source]["event_count"]
        if len(observed) != declared_count:
            findings["web_evidence_count_mismatch"] += 1
            incomplete = True
        sequences = sorted(event["sequence"] for event in observed)
        if sequences != list(range(len(observed))):
            findings["web_evidence_sequence_gap"] += 1
            incomplete = True
        if not streams[source]["complete"]:
            findings[_STREAM_LOSS_FINDING[source]] += 1
            incomplete = True
        stream_summary[source] = {
            "declared_event_count": declared_count,
            "observed_event_count": len(observed),
            "complete": streams[source]["complete"],
        }

    if len(events) > normalized_request["budgets"]["max_events"]:
        findings["web_event_budget_exceeded"] += 1
        incomplete = True
    redirect_count = sum(event["kind"] == "redirect" for event in events)
    if redirect_count > normalized_request["budgets"]["max_redirects"]:
        findings["web_redirect_budget_exceeded"] += 1
        incomplete = True
    if not any(event["kind"] == "browser_sandbox" for event in events):
        findings["web_browser_sandbox_unknown"] += 1
        incomplete = True
    if not any(event["kind"] == "navigation" for event in events):
        findings["web_navigation_missing"] += 1
        incomplete = True

    for source, finding_id in (
        ("browser", "web_browser_lifecycle_incomplete"),
        ("vm", "web_vm_lifecycle_incomplete"),
    ):
        lifecycle = {
            event["disposition"]
            for event in source_events[source]
            if event["kind"] == "lifecycle"
        }
        if not {"started", "stopped"}.issubset(lifecycle):
            findings[finding_id] += 1
            incomplete = True

    finding_items = _finding_items(findings)
    decision = "DENY" if incomplete or finding_items else "ALLOW"
    return {
        "evidence_version": EVIDENCE_VERSION,
        "complete": not incomplete,
        "telemetry_incomplete": incomplete,
        "fail_closed": incomplete,
        "decision": decision,
        "events_observed": len(events),
        "streams": stream_summary,
        "findings": finding_items,
    }


__all__ = [
    "EVIDENCE_VERSION",
    "EVENT_KEYS",
    "TELEMETRY_INCOMPLETE_FINDINGS",
    "connect_authority_for_origin",
    "normalize_connect_authority",
    "reduce_browser_evidence",
    "validate_browser_event",
    "validate_browser_evidence",
]
