"""Strict browser-probe contracts and deterministic evidence reduction.

This module is intentionally independent of Chromium and Firecracker.  The
host validates a request before starting either of them, and reduces trusted
metadata after teardown.  Page text, response bodies, query strings, and
model-authored interpretations never appear in the evidence contract.

Hostname validation is only the first SSRF boundary.  The egress broker must
also call :func:`validate_resolved_address` for every DNS answer and again for
the address actually used for each connection.  That second check prevents a
public-looking hostname from reaching a private address through DNS rebinding.
"""

from __future__ import annotations

import copy
import ipaddress
import re
import unicodedata
from collections import Counter
from typing import Any, Iterable
from urllib.parse import quote, urlsplit, urlunsplit


CONTRACT_VERSION = "cindermote.browser-probe/v1"
EVIDENCE_VERSION = "cindermote.browser-evidence/v1"

MAX_URL_LENGTH = 4096
MAX_AUTHORIZED_ORIGINS = 16
MAX_EVIDENCE_EVENTS = 100_000

DEFAULT_BUDGETS = {
    "wall_clock_sec": 20,
    "cpu_vcpu": 1,
    "ram_mib": 1024,
    "max_network_bytes": 16 * 1024 * 1024,
    "max_events": 10_000,
    "max_redirects": 8,
}

# There is no active browsing mode in v1.  These controls are redundant by
# design: a malformed caller cannot turn "passive" into clicks or uploads by
# adding a second field with different semantics.
PASSIVE_NAVIGATION = {
    "mode": "passive",
    "allow_clicks": False,
    "allow_typing": False,
    "allow_uploads": False,
    "allow_downloads": False,
    "allow_permission_grants": False,
    "allow_popups": False,
    "max_tabs": 1,
}

REQUEST_KEYS = {
    "contract_version",
    "url",
    "authorized_origins",
    "navigation",
    "budgets",
}
BUDGET_KEYS = set(DEFAULT_BUDGETS)
NAVIGATION_KEYS = set(PASSIVE_NAVIGATION)

_BUDGET_RANGES = {
    "wall_clock_sec": (1, 60),
    "cpu_vcpu": (1, 2),
    "ram_mib": (256, 4096),
    "max_network_bytes": (1, 64 * 1024 * 1024),
    "max_events": (1, MAX_EVIDENCE_EVENTS),
    "max_redirects": (0, 20),
}

_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_PERCENT_ESCAPE = re.compile(r"%([0-9a-fA-F]{2})")
_INVALID_PERCENT = re.compile(r"%(?![0-9a-fA-F]{2})")
_NUMERIC_HOST_LABEL = re.compile(r"^(?:0x[0-9a-f]+|[0-9]+)$", re.IGNORECASE)

# Special-use, multicast-DNS, anonymity, and conventional private suffixes are
# not meaningful public-web authorities for this probe.  Resolved IP checks
# remain mandatory because this list cannot protect against DNS rebinding.
_UNSAFE_HOST_SUFFIXES = {
    "localhost",
    "local",
    "localdomain",
    "internal",
    "intranet",
    "corp",
    "home",
    "lan",
    "home.arpa",
    "onion",
    "invalid",
    "test",
    "example",
}

REQUIRED_STREAMS = ("browser", "cdp", "egress", "vm")
EVIDENCE_KEYS = {"evidence_version", "events", "streams"}
STREAM_STATUS_KEYS = {"complete", "event_count"}
EVENT_KEYS = {"sequence", "source", "kind", "origin", "disposition"}

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
    "network_consistency": {"matched", "mismatched"},
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
    "network_consistency": {"egress", "vm"},
    "telemetry_loss": set(REQUIRED_STREAMS),
}

_ORIGIN_REQUIRED_KINDS = {"navigation", "redirect", "network_request"}

FINDING_SEVERITIES = {
    "web_active_interaction_attempt": "CRITICAL",
    "web_blocked_egress_attempt": "HIGH",
    "web_browser_execution_failed": "CRITICAL",
    "web_browser_lifecycle_incomplete": "CRITICAL",
    "web_browser_sandbox_inactive": "CRITICAL",
    "web_browser_sandbox_unknown": "CRITICAL",
    "web_browser_telemetry_loss": "CRITICAL",
    "web_cdp_telemetry_loss": "CRITICAL",
    "web_download_attempt": "HIGH",
    "web_egress_telemetry_loss": "CRITICAL",
    "web_event_budget_exceeded": "CRITICAL",
    "web_evidence_count_mismatch": "CRITICAL",
    "web_evidence_schema_invalid": "CRITICAL",
    "web_evidence_sequence_gap": "CRITICAL",
    "web_file_upload_attempt": "CRITICAL",
    "web_host_guest_network_mismatch": "CRITICAL",
    "web_host_guest_network_unknown": "CRITICAL",
    "web_mixed_content_observed": "HIGH",
    "web_navigation_failed": "HIGH",
    "web_navigation_missing": "CRITICAL",
    "web_popup_attempt": "HIGH",
    "web_prompt_marker_hidden": "HIGH",
    "web_prompt_marker_visible": "HIGH",
    "web_redirect_budget_exceeded": "CRITICAL",
    "web_unauthorized_origin_attempt": "CRITICAL",
    "web_vm_execution_failed": "CRITICAL",
    "web_vm_lifecycle_incomplete": "CRITICAL",
    "web_vm_telemetry_loss": "CRITICAL",
}

# These findings are emitted only on reducer paths where the evidence cannot
# be treated as complete.  Receipt validation imports this set so a signed
# summary cannot relabel an incomplete reduction as complete without also
# changing the canonical reducer contract.
TELEMETRY_INCOMPLETE_FINDINGS = frozenset(
    {
        "web_browser_execution_failed",
        "web_browser_lifecycle_incomplete",
        "web_browser_sandbox_unknown",
        "web_browser_telemetry_loss",
        "web_cdp_telemetry_loss",
        "web_egress_telemetry_loss",
        "web_event_budget_exceeded",
        "web_evidence_count_mismatch",
        "web_evidence_schema_invalid",
        "web_evidence_sequence_gap",
        "web_host_guest_network_unknown",
        "web_navigation_failed",
        "web_navigation_missing",
        "web_redirect_budget_exceeded",
        "web_vm_execution_failed",
        "web_vm_lifecycle_incomplete",
        "web_vm_telemetry_loss",
    }
)

_STREAM_LOSS_FINDING = {
    "browser": "web_browser_telemetry_loss",
    "cdp": "web_cdp_telemetry_loss",
    "egress": "web_egress_telemetry_loss",
    "vm": "web_vm_telemetry_loss",
}


class BrowserContractError(ValueError):
    """Raised when a browser request or evidence object is not conformant."""


def _canonicalize_escapes(value: str) -> str:
    if _INVALID_PERCENT.search(value):
        raise BrowserContractError("URL contains an invalid percent escape")
    return _PERCENT_ESCAPE.sub(lambda match: "%" + match.group(1).upper(), value)


def _normalize_hostname(hostname: str) -> str:
    if not hostname or hostname.endswith(".") or hostname.startswith("."):
        raise BrowserContractError("URL hostname is empty or ambiguous")
    if "%" in hostname or "\\" in hostname or ":" in hostname:
        raise BrowserContractError("URL hostname is not a DNS name")

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise BrowserContractError("IP literals are not permitted")

    try:
        ascii_hostname = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise BrowserContractError("URL hostname is not valid IDNA") from exc

    if len(ascii_hostname) > 253:
        raise BrowserContractError("URL hostname is too long")
    labels = ascii_hostname.split(".")
    if len(labels) < 2 or any(not _HOST_LABEL.fullmatch(label) for label in labels):
        raise BrowserContractError("URL hostname must be a public-style DNS name")
    if all(_NUMERIC_HOST_LABEL.fullmatch(label) for label in labels):
        # Browsers historically accept shortened, octal, hexadecimal, and
        # integer IPv4 spellings that strict IP parsers do not.
        raise BrowserContractError("numeric host spellings are not permitted")
    if labels[-1].isdigit():
        raise BrowserContractError("numeric top-level domains are not permitted")
    for suffix in _UNSAFE_HOST_SUFFIXES:
        if ascii_hostname == suffix or ascii_hostname.endswith("." + suffix):
            raise BrowserContractError("private or special-use hostname is not permitted")
    return ascii_hostname


def normalize_url(value: str) -> str:
    """Return one canonical HTTP(S) URL or raise ``BrowserContractError``.

    Credentials, fragments, IP spellings, single-label/private hostnames,
    backslashes, control characters, and malformed escapes are rejected.  A
    default port is removed because it is not distinct in the web-origin model;
    a non-default port remains part of both the URL and its exact origin.
    """

    if not isinstance(value, str) or not value or len(value) > MAX_URL_LENGTH:
        raise BrowserContractError("URL must be a bounded non-empty string")
    if value != value.strip() or any(
        ord(character) <= 0x20 or ord(character) == 0x7F for character in value
    ):
        raise BrowserContractError("URL contains whitespace or a control character")
    if "\\" in value:
        # Chromium treats backslashes as authority/path separators for special
        # schemes while generic URL parsers often do not.
        raise BrowserContractError("URL backslashes are not permitted")
    if "#" in value:
        raise BrowserContractError("URL fragments are not permitted")

    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise BrowserContractError("URL cannot be parsed") from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.netloc:
        raise BrowserContractError("URL scheme must be http or https")
    if "@" in parsed.netloc or parsed.username is not None or parsed.password is not None:
        raise BrowserContractError("URL credentials are not permitted")
    if parsed.hostname is None:
        raise BrowserContractError("URL hostname is required")

    hostname = _normalize_hostname(parsed.hostname)
    try:
        port = parsed.port
    except ValueError as exc:
        raise BrowserContractError("URL port is invalid") from exc
    if port is not None and port < 1:
        raise BrowserContractError("URL port is invalid")
    if parsed.netloc.endswith(":"):
        raise BrowserContractError("URL port is empty")
    default_port = 80 if scheme == "http" else 443
    authority = hostname if port in {None, default_port} else f"{hostname}:{port}"

    path = parsed.path or "/"
    path = unicodedata.normalize("NFC", path)
    query = unicodedata.normalize("NFC", parsed.query)
    path = quote(path, safe="/%:@!$&'()*+,;=-._~")
    query = quote(query, safe="/%?:@!$&'()*+,;=-._~")
    path = _canonicalize_escapes(path)
    query = _canonicalize_escapes(query)
    normalized = urlunsplit((scheme, authority, path, query, ""))
    if len(normalized) > MAX_URL_LENGTH:
        raise BrowserContractError("normalized URL is too long")
    return normalized


def origin_for_url(value: str) -> str:
    """Return the canonical ``scheme://host[:port]`` origin for a URL."""

    parsed = urlsplit(normalize_url(value))
    return f"{parsed.scheme}://{parsed.netloc}"


def normalize_origin(value: str) -> str:
    """Validate and canonicalize an exact web origin, not an origin pattern."""

    if not isinstance(value, str) or "?" in value or "#" in value:
        raise BrowserContractError("authorized origin cannot contain query or fragment data")
    normalized_url = normalize_url(value)
    parsed = urlsplit(normalized_url)
    if parsed.path != "/" or parsed.query:
        raise BrowserContractError("authorized origin cannot contain a path")
    return f"{parsed.scheme}://{parsed.netloc}"


def validate_resolved_address(value: str) -> str:
    """Return a canonical public unicast IP or reject an unsafe DNS answer.

    The egress broker must apply this to every answer and the connected peer;
    accepting a hostname based only on :func:`normalize_url` is insufficient.
    """

    if not isinstance(value, str) or not value or value != value.strip() or "%" in value:
        raise BrowserContractError("resolved address must be a plain IP literal")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise BrowserContractError("resolved address is not an IP literal") from exc
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if (
        not address.is_global
        or address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        raise BrowserContractError("resolved address is not public unicast")
    return address.compressed


def is_authorized_url(value: str, authorized_origins: Iterable[str]) -> bool:
    """Return whether a URL belongs to one of the exact declared origins."""

    candidate = origin_for_url(value)
    allowed = {normalize_origin(origin) for origin in authorized_origins}
    return candidate in allowed


def _validate_navigation(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != NAVIGATION_KEYS:
        raise BrowserContractError("navigation has missing or extra fields")
    for key, expected in PASSIVE_NAVIGATION.items():
        actual = value[key]
        if isinstance(expected, bool):
            valid = actual is expected
        elif isinstance(expected, int):
            valid = isinstance(actual, int) and not isinstance(actual, bool) and actual == expected
        else:
            valid = isinstance(actual, str) and actual == expected
        if not valid:
            raise BrowserContractError(f"navigation.{key} violates passive-only mode")
    return copy.deepcopy(PASSIVE_NAVIGATION)


def _validate_budgets(value: Any) -> dict[str, int]:
    if not isinstance(value, dict) or set(value) != BUDGET_KEYS:
        raise BrowserContractError("budgets has missing or extra fields")
    normalized: dict[str, int] = {}
    for key in DEFAULT_BUDGETS:
        candidate = value[key]
        minimum, maximum = _BUDGET_RANGES[key]
        if (
            not isinstance(candidate, int)
            or isinstance(candidate, bool)
            or not minimum <= candidate <= maximum
        ):
            raise BrowserContractError(
                f"budgets.{key} must be an integer in {minimum}..{maximum}"
            )
        normalized[key] = candidate
    return normalized


def validate_probe_request(value: Any) -> dict[str, Any]:
    """Validate a request and return its canonical, deterministic form."""

    if not isinstance(value, dict) or set(value) != REQUEST_KEYS:
        raise BrowserContractError("browser request has missing or extra fields")
    if value["contract_version"] != CONTRACT_VERSION:
        raise BrowserContractError("unsupported browser contract version")

    url = normalize_url(value["url"])
    origins_value = value["authorized_origins"]
    if (
        not isinstance(origins_value, list)
        or not 1 <= len(origins_value) <= MAX_AUTHORIZED_ORIGINS
    ):
        raise BrowserContractError("authorized_origins must be a bounded non-empty list")
    origins = [normalize_origin(origin) for origin in origins_value]
    if len(set(origins)) != len(origins):
        raise BrowserContractError("authorized_origins contains canonical duplicates")
    origins = sorted(origins)
    if origin_for_url(url) not in origins:
        raise BrowserContractError("initial URL origin is not explicitly authorized")

    return {
        "contract_version": CONTRACT_VERSION,
        "url": url,
        "authorized_origins": origins,
        "navigation": _validate_navigation(value["navigation"]),
        "budgets": _validate_budgets(value["budgets"]),
    }


def make_probe_request(
    url: str,
    *,
    authorized_origins: Iterable[str] | None = None,
    budgets: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Build a complete v1 request from safe defaults, then validate it."""

    normalized_url = normalize_url(url)
    origins = (
        [origin_for_url(normalized_url)]
        if authorized_origins is None
        else list(authorized_origins)
    )
    merged_budgets = dict(DEFAULT_BUDGETS)
    if budgets is not None:
        if not isinstance(budgets, dict) or set(budgets) - BUDGET_KEYS:
            raise BrowserContractError("budget override contains an unknown field")
        merged_budgets.update(budgets)
    return validate_probe_request(
        {
            "contract_version": CONTRACT_VERSION,
            "url": normalized_url,
            "authorized_origins": origins,
            "navigation": copy.deepcopy(PASSIVE_NAVIGATION),
            "budgets": merged_budgets,
        }
    )


def validate_browser_event(value: Any) -> dict[str, Any]:
    """Validate one metadata-only browser event and return a canonical copy."""

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
    if kind not in _KIND_DISPOSITIONS:
        raise BrowserContractError("browser event kind is invalid")
    if source not in _KIND_SOURCES[kind]:
        raise BrowserContractError("browser event source cannot emit this kind")
    disposition = value["disposition"]
    if disposition not in _KIND_DISPOSITIONS[kind]:
        raise BrowserContractError("browser event disposition is invalid")

    origin_value = value["origin"]
    if origin_value is None:
        origin = None
    elif isinstance(origin_value, str):
        origin = normalize_origin(origin_value)
    else:
        raise BrowserContractError("browser event origin must be an origin or null")
    if kind in _ORIGIN_REQUIRED_KINDS and origin is None:
        raise BrowserContractError("browser event kind requires an origin")

    return {
        "sequence": sequence,
        "source": source,
        "kind": kind,
        "origin": origin,
        "disposition": disposition,
    }


def validate_browser_evidence(value: Any) -> dict[str, Any]:
    """Validate an evidence bundle without deciding whether it is complete."""

    if not isinstance(value, dict) or set(value) != EVIDENCE_KEYS:
        raise BrowserContractError("browser evidence has missing or extra fields")
    if value["evidence_version"] != EVIDENCE_VERSION:
        raise BrowserContractError("unsupported browser evidence version")
    events_value = value["events"]
    if not isinstance(events_value, list) or len(events_value) > MAX_EVIDENCE_EVENTS:
        raise BrowserContractError("browser evidence events must be a bounded list")
    events = [validate_browser_event(event) for event in events_value]

    streams_value = value["streams"]
    if not isinstance(streams_value, dict) or set(streams_value) != set(REQUIRED_STREAMS):
        raise BrowserContractError("browser evidence stream set is incomplete")
    streams: dict[str, dict[str, Any]] = {}
    for source in REQUIRED_STREAMS:
        status = streams_value[source]
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
    """Reduce browser evidence to stable finding IDs and a fail-closed verdict.

    This function deliberately returns ``DENY`` rather than raising for any
    malformed request/evidence pair.  Schema validity, complete trusted
    streams, contiguous per-stream sequences, matching counts, lifecycle
    closure, a sandbox attestation, a network-consistency attestation, and a
    navigation result are all required before ``complete`` can be true.
    """

    try:
        normalized_request = validate_probe_request(request)
        normalized_evidence = validate_browser_evidence(evidence)
    except Exception:
        # Reducer callers must never accidentally convert parser failure into a
        # clean result.  The fixed ID also avoids reflecting attacker text.
        return _closed_reduction("web_evidence_schema_invalid")

    events = normalized_evidence["events"]
    streams = normalized_evidence["streams"]
    allowed_origins = set(normalized_request["authorized_origins"])
    findings: Counter[str] = Counter()
    incomplete = False

    source_events: dict[str, list[dict[str, Any]]] = {
        source: [] for source in REQUIRED_STREAMS
    }
    for event in events:
        source_events[event["source"]].append(event)
        kind = event["kind"]
        disposition = event["disposition"]
        origin = event["origin"]

        if kind in _ORIGIN_REQUIRED_KINDS and origin not in allowed_origins:
            findings["web_unauthorized_origin_attempt"] += 1
        if kind == "network_request" and disposition == "blocked":
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
        elif kind == "network_consistency" and disposition == "mismatched":
            findings["web_host_guest_network_mismatch"] += 1
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

    sandbox_events = [event for event in events if event["kind"] == "browser_sandbox"]
    if not sandbox_events:
        findings["web_browser_sandbox_unknown"] += 1
        incomplete = True

    consistency_events = [
        event for event in events if event["kind"] == "network_consistency"
    ]
    if not consistency_events:
        findings["web_host_guest_network_unknown"] += 1
        incomplete = True

    navigation_events = [event for event in events if event["kind"] == "navigation"]
    if not navigation_events:
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
    "BrowserContractError",
    "CONTRACT_VERSION",
    "DEFAULT_BUDGETS",
    "EVIDENCE_VERSION",
    "FINDING_SEVERITIES",
    "PASSIVE_NAVIGATION",
    "REQUIRED_STREAMS",
    "TELEMETRY_INCOMPLETE_FINDINGS",
    "is_authorized_url",
    "make_probe_request",
    "normalize_origin",
    "normalize_url",
    "origin_for_url",
    "reduce_browser_evidence",
    "validate_browser_event",
    "validate_browser_evidence",
    "validate_probe_request",
    "validate_resolved_address",
]
