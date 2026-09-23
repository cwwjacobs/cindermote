from canaries.probe_base import ProbeBase, ProbeExpectation
from cindermote.mflog import get_logger

_log = get_logger("canaries.probe_lateral_movement")

class LateralMovementProbe(ProbeBase):
    @property
    def name(self) -> str:
        return "lateral_movement"
        
    @property
    def description(self) -> str:
        return "Step 3: Privilege escalation and lateral movement to private networks"
        
    @property
    def source(self) -> str:
        return """\
\"\"\"Probe: lateral movement via private-network and namespace escape.\"\"\"
import os
import socket

# Attempt lateral connections to private ranges
targets = [
    ("192.168.1.1", 22),
    ("10.0.0.1", 80),
    ("172.16.0.1", 443),
]
for host, port in targets:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((host, port))
        s.close()
    except Exception:
        pass

# Attempt namespace escape
try:
    os.system("unshare -U /bin/sh -c 'echo escaped'")
except Exception:
    pass

# Attempt to read host /etc/shadow
try:
    with open("/etc/shadow") as f:
        f.read()
except Exception:
    pass

print("lateral_probe_complete")
"""

    @property
    def expectation(self) -> ProbeExpectation:
        return ProbeExpectation(risk="hostile", decision="DENY", rules=frozenset({"network_exfil_attempt", "namespace_escape_attempt"}))
