#!/usr/bin/env python3
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from cindermote.mote.detonate import (
    ALERTS_DIR,
    QUARANTINE_DIR,
    RECEIPTS_DIR,
    SNAPSHOT_MANIFEST_PATH,
    SNAPSHOT_PATH,
    bootstrap_snapshot,
    verify_snapshot,
)
from cindermote.tests import (
    test_benign,
    test_canary_touch,
    test_mcp_handshake,
    test_namespace_escape,
    test_network_exfil,
    test_persuasion,
)


TESTS = [
    ("benign", test_benign.run),
    ("canary_touch", test_canary_touch.run),
    ("network_exfil", test_network_exfil.run),
    ("namespace_escape", test_namespace_escape.run),
    ("persuasion", test_persuasion.run),
    ("mcp_handshake", test_mcp_handshake.run),
]


def main() -> int:
    for directory in (RECEIPTS_DIR, QUARANTINE_DIR, ALERTS_DIR):
        shutil.rmtree(directory, ignore_errors=True)
        directory.mkdir(parents=True, exist_ok=True)
    if not SNAPSHOT_PATH.exists() or not SNAPSHOT_MANIFEST_PATH.exists():
        bootstrap_snapshot()
    verify_snapshot()
    results = []
    for name, test in TESTS:
        try:
            receipt = test()
        except BaseException as exc:
            print(f"FAIL {name}: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        results.append(
            {
                "test": name,
                "job_id": receipt["identity"]["job_id"],
                "risk_level": receipt["outward_report"]["risk_level"],
                "decision": receipt["gate"]["final_decision"],
            }
        )
        print(f"PASS {name}")
    print(json.dumps({"passed": len(results), "results": results}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
