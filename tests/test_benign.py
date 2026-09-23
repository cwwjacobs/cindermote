from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from cindermote.mote.detonate import detonate


def run() -> dict:
    with TemporaryDirectory(prefix="cindermote-test-") as directory:
        artifact = Path(directory) / "benign.py"
        artifact.write_text('print("hello world")\n', encoding="utf-8")
        receipt = detonate(artifact, "python-script", submitted_by="self-test")
    assert receipt["outward_report"]["risk_level"] == "benign"
    assert receipt["gate"]["final_decision"] == "ALLOW"
    assert not receipt["outward_report"]["canaries_tripped"]
    assert not receipt["detector_findings"]
    assert receipt["isolation"]["namespace_used"] is True
    assert receipt["isolation"]["seccomp_loaded"] is True
    assert receipt["purge"]["verified_externally"] is True
    return receipt
