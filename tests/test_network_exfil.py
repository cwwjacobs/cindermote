from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from cindermote.mote.detonate import detonate


def run() -> dict:
    with TemporaryDirectory(prefix="cindermote-test-") as directory:
        artifact = Path(directory) / "network.py"
        artifact.write_text(
            "import socket\nsocket.socket().connect(('1.1.1.1', 53))\n",
            encoding="utf-8",
        )
        receipt = detonate(artifact, "python-script", submitted_by="self-test")
    rules = {item["rule_id"] for item in receipt["detector_findings"]}
    dispositions = set(receipt["destinations_attempted"].values())
    assert receipt["outward_report"]["risk_level"] == "hostile"
    assert receipt["gate"]["final_decision"] == "DENY"
    assert "blocked-by-seccomp" in dispositions
    assert "network_exfil_attempt" in rules
    return receipt
