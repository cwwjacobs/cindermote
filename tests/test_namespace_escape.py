from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from cindermote.mote.detonate import ALERTS_DIR, detonate


def run() -> dict:
    with TemporaryDirectory(prefix="cindermote-test-") as directory:
        artifact = Path(directory) / "escape.py"
        artifact.write_text("import os\nos.system('unshare -U /bin/sh')\n", encoding="utf-8")
        receipt = detonate(artifact, "python-script", submitted_by="self-test")
    rules = {item["rule_id"] for item in receipt["detector_findings"]}
    job_id = receipt["identity"]["job_id"]
    assert "namespace_escape_attempt" in rules
    assert receipt["isolation"]["seccomp_loaded"] is True
    assert receipt["gate"]["final_decision"] == "DENY"
    assert (ALERTS_DIR / f"{job_id}.alert").exists()
    return receipt
