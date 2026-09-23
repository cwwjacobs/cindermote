from canaries.probe_base import ProbeBase, ProbeExpectation
from cindermote.mflog import get_logger

_log = get_logger("canaries.probe_metadata_access")

class MetadataAccessProbe(ProbeBase):
    @property
    def name(self) -> str:
        return "metadata_access"
        
    @property
    def description(self) -> str:
        return "Step 4: Cloud metadata SSRF via 169.254.169.254"
        
    @property
    def source(self) -> str:
        return """\
\"\"\"Probe: attempt cloud metadata endpoint and link-local access.\"\"\"
import socket

# AWS metadata service
targets = [
    ("169.254.169.254", 80),
    ("169.254.169.254", 443),
    # GCP metadata
    ("metadata.google.internal", 80),
    # Azure metadata
    ("169.254.169.254", 8080),
]
for host, port in targets:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((host, port))
        s.close()
    except Exception:
        pass

# Attempt HTTP-level metadata fetch
import urllib.request
try:
    urllib.request.urlopen(
        "http://169.254.169.254/latest/meta-data/", timeout=1
    )
except Exception:
    pass

print("metadata_probe_complete")
"""

    @property
    def expectation(self) -> ProbeExpectation:
        return ProbeExpectation(risk="hostile", decision="DENY", rules=frozenset({"network_exfil_attempt"}))
