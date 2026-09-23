"""Tests for cindermote.logging structured logger."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

# Ensure project is importable
THIS_FILE = Path(__file__).resolve()
PROJECT_DIR = THIS_FILE.parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from cindermote.mflog import StructuredLogger, configure, get_logger, get_run_id, set_run_id


def test_get_logger_caches_instances():
    """Same component name returns the same logger instance."""
    a = get_logger("test.cache")
    b = get_logger("test.cache")
    assert a is b


def test_get_logger_different_components():
    """Different component names return different logger instances."""
    a = get_logger("test.alpha")
    b = get_logger("test.beta")
    assert a is not b


def test_logger_emits_valid_json():
    """Logger output is valid JSON with required fields."""
    buf = io.StringIO()
    configure(min_severity="DEBUG", output=buf)
    log = get_logger("test.json_output")
    log.info("test_event", "Test message", data={"key": "value"})

    line = buf.getvalue().strip()
    record = json.loads(line)

    assert record["severity"] == "INFO"
    assert record["component"] == "test.json_output"
    assert record["event"] == "test_event"
    assert record["msg"] == "Test message"
    assert record["data"] == {"key": "value"}
    assert "ts" in record
    assert "ts_mono" in record


def test_severity_filtering():
    """Events below min_severity are not emitted."""
    buf = io.StringIO()
    configure(min_severity="WARN", output=buf)
    log = get_logger("test.severity_filter")
    log.debug("debug_event", "Should not appear")
    log.info("info_event", "Should not appear")
    log.warn("warn_event", "Should appear")

    lines = [l for l in buf.getvalue().strip().split("\n") if l]
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["event"] == "warn_event"


def test_run_id_correlation():
    """set_run_id() injects run_id into log records."""
    buf = io.StringIO()
    configure(min_severity="DEBUG", output=buf)
    set_run_id("test-run-123")
    log = get_logger("test.run_id")
    log.info("correlated_event", "Should have run_id")

    record = json.loads(buf.getvalue().strip())
    assert record.get("run_id") == "test-run-123"

    # Cleanup
    set_run_id(None)


def test_run_id_absent_when_unset():
    """When no run_id is set, records should not contain run_id key."""
    buf = io.StringIO()
    configure(min_severity="DEBUG", output=buf)
    set_run_id(None)
    log = get_logger("test.no_run_id")
    log.info("uncorrelated_event", "No run_id expected")

    record = json.loads(buf.getvalue().strip())
    assert "run_id" not in record


def test_all_severity_levels():
    """All five severity levels emit valid records."""
    buf = io.StringIO()
    configure(min_severity="DEBUG", output=buf)
    log = get_logger("test.all_levels")

    log.debug("d", "debug")
    log.info("i", "info")
    log.warn("w", "warn")
    log.error("e", "error")
    log.fatal("f", "fatal")

    lines = [l for l in buf.getvalue().strip().split("\n") if l]
    assert len(lines) == 5
    severities = [json.loads(l)["severity"] for l in lines]
    assert severities == ["DEBUG", "INFO", "WARN", "ERROR", "FATAL"]


def test_data_field_optional():
    """Records without data= omit the data field."""
    buf = io.StringIO()
    configure(min_severity="DEBUG", output=buf)
    log = get_logger("test.no_data")
    log.info("simple_event", "No data")

    record = json.loads(buf.getvalue().strip())
    assert "data" not in record


if __name__ == "__main__":
    # Reset to stderr for other tests after this
    test_get_logger_caches_instances()
    test_get_logger_different_components()
    test_logger_emits_valid_json()
    test_severity_filtering()
    test_run_id_correlation()
    test_run_id_absent_when_unset()
    test_all_severity_levels()
    test_data_field_optional()
    # Restore default output
    configure(min_severity="INFO", output=sys.stderr)
    print("All logging tests passed ✅")
