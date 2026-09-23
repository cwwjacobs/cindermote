from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from cindermote.mote.detonate import detonate


def run() -> dict:
    with TemporaryDirectory(prefix="cindermote-test-") as directory:
        artifact = Path(directory) / "canary.py"
        artifact.write_text("open('/home/mote/.aws/credentials').read()\n", encoding="utf-8")
        receipt = detonate(artifact, "python-script", submitted_by="self-test")
    rules = {item["rule_id"] for item in receipt["detector_findings"]}
    assert receipt["outward_report"]["risk_level"] == "hostile"
    assert receipt["gate"]["final_decision"] == "DENY"
    assert "canary_cred_aws" in receipt["outward_report"]["canaries_tripped"]
    assert "cred_harvest_pattern" in rules
    return receipt
