"""Cindermote structured logging — JSON-lines, severity-tagged, run-correlated.

Every log record is a self-contained JSON object written to a single line on
stderr (or a configured file descriptor).  Records carry:

    - ``ts``          ISO-8601 wall-clock timestamp
    - ``ts_mono``     monotonic seconds since process start (float)
    - ``severity``    DEBUG / INFO / WARN / ERROR / FATAL
    - ``component``   dotted module tag (e.g. ``agent_probe.broker``)
    - ``run_id``      correlation ID for the current detonation run (optional)
    - ``event``       machine-readable event code (snake_case)
    - ``msg``         human-readable description
    - ``data``        optional dict of structured key-value pairs

Design constraints:
    - No dependency on stdlib ``logging`` — we need deterministic output and
      cannot tolerate handler chains that swallow or reformat security events.
    - Thread-safe: a single reentrant lock guards writes.
    - Fail-open on write errors: a missed log line must never abort a
      detonation or gate evaluation.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import sys
import threading
import time
from typing import Any, TextIO


_SEVERITIES = ("DEBUG", "INFO", "WARN", "ERROR", "FATAL")
_SEVERITY_SET = frozenset(_SEVERITIES)
_PROCESS_START_MONO = time.monotonic()
_LOCK = threading.RLock()

# Global run-ID: set once per detonation via set_run_id().
_run_id: str | None = None

# Global minimum severity for output filtering.
_min_severity: int = 1  # INFO by default

# Output stream — defaults to stderr, can be redirected.
_output: TextIO = sys.stderr


def _severity_rank(severity: str) -> int:
    try:
        return _SEVERITIES.index(severity)
    except ValueError:
        return 0


def configure(
    *,
    min_severity: str = "INFO",
    output: TextIO | None = None,
) -> None:
    """Configure global logging parameters.  Safe to call multiple times."""
    global _min_severity, _output
    with _LOCK:
        _min_severity = _severity_rank(min_severity)
        if output is not None:
            _output = output


def set_run_id(run_id: str | None) -> None:
    """Bind a correlation ID for the current detonation run."""
    global _run_id
    with _LOCK:
        _run_id = run_id


def get_run_id() -> str | None:
    """Return the current run correlation ID, if set."""
    with _LOCK:
        return _run_id


def _emit(record: dict[str, Any]) -> None:
    """Write one JSON-lines record to the output stream."""
    try:
        line = json.dumps(record, default=str, separators=(",", ":"))
        with _LOCK:
            _output.write(line)
            _output.write("\n")
            _output.flush()
    except Exception:
        # Fail-open: never let a log write crash the system.
        pass


class StructuredLogger:
    """Component-scoped structured logger.

    Usage::

        from cindermote.mflog import get_logger
        log = get_logger("agent_probe.broker")
        log.info("proposal_evaluated", "Broker evaluated proposal", data={"seq": 3})
    """

    __slots__ = ("_component",)

    def __init__(self, component: str) -> None:
        self._component = component

    def _log(
        self,
        severity: str,
        event: str,
        msg: str,
        data: dict[str, Any] | None = None,
    ) -> None:
        if _severity_rank(severity) < _min_severity:
            return
        record: dict[str, Any] = {
            "ts": dt.datetime.now(dt.timezone.utc).isoformat(),
            "ts_mono": round(time.monotonic() - _PROCESS_START_MONO, 6),
            "severity": severity,
            "component": self._component,
            "event": event,
            "msg": msg,
        }
        current_run = get_run_id()
        if current_run is not None:
            record["run_id"] = current_run
        if data:
            record["data"] = data
        _emit(record)

    def debug(self, event: str, msg: str, **kwargs: Any) -> None:
        self._log("DEBUG", event, msg, kwargs.get("data"))

    def info(self, event: str, msg: str, **kwargs: Any) -> None:
        self._log("INFO", event, msg, kwargs.get("data"))

    def warn(self, event: str, msg: str, **kwargs: Any) -> None:
        self._log("WARN", event, msg, kwargs.get("data"))

    def error(self, event: str, msg: str, **kwargs: Any) -> None:
        self._log("ERROR", event, msg, kwargs.get("data"))

    def fatal(self, event: str, msg: str, **kwargs: Any) -> None:
        self._log("FATAL", event, msg, kwargs.get("data"))


# Logger cache: one instance per component name.
_loggers: dict[str, StructuredLogger] = {}


def get_logger(component: str) -> StructuredLogger:
    """Return (or create) a structured logger for the given component.

    Cached so that ``get_logger("x") is get_logger("x")`` holds.
    """
    with _LOCK:
        logger = _loggers.get(component)
        if logger is None:
            logger = StructuredLogger(component)
            _loggers[component] = logger
        return logger


__all__ = [
    "StructuredLogger",
    "configure",
    "get_logger",
    "get_run_id",
    "set_run_id",
]
