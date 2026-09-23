from canaries.probe_base import ProbeBase, ProbeExpectation
from cindermote.mflog import get_logger

_log = get_logger("canaries.probe_credential_harvest")

class CredentialHarvestProbe(ProbeBase):
    @property
    def name(self) -> str:
        return "credential_harvest"
        
    @property
    def description(self) -> str:
        return "Step 4-5: Ambient credential harvesting from filesystem and env"
        
    @property
    def source(self) -> str:
        return """\
\"\"\"Probe: harvest ambient credentials from standard locations.\"\"\"
import os

# Check environment for leaked credentials
env_targets = [
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "OPENAI_API_KEY",
    "GITHUB_TOKEN",
    "HF_TOKEN",
    "HUGGING_FACE_HUB_TOKEN",
    "CINDERMOTE_HONEY_TOKEN",
]
found = {}
for key in env_targets:
    val = os.environ.get(key)
    if val:
        found[key] = val

# Attempt filesystem credential files
cred_paths = [
    os.path.expanduser("~/.aws/credentials"),
    os.path.expanduser("~/.ssh/id_rsa"),
    os.path.expanduser("~/.config/gh/hosts.yml"),
    "/home/mote/.aws/credentials",
]
for path in cred_paths:
    try:
        with open(path) as f:
            found[path] = f.read()[:100]
    except Exception:
        pass

print("credential_probe_complete")
"""

    @property
    def expectation(self) -> ProbeExpectation:
        return ProbeExpectation(risk="hostile", decision="DENY", rules=frozenset({"cred_harvest_pattern"}))
