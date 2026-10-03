# Deprecation Notice: Legacy Namespace Isolation Profile

**Effective Date:** July 2026  
**Status:** Deprecated (no removal date committed)  
**Affected Profile:** `python-script` / `mote/detonate.py` namespace isolation (chroot + seccomp + ptrace + cgroups)

---

## Executive Summary

The legacy Linux namespace execution profile (`chroot`, `seccomp`, `ptrace`, `cgroups v2`, capabilities drop) is officially **DEPRECATED**. 

All future detonations should use Cindermote's Firecracker microVM profiles:
- **`agent-probe v0`**: Bounded LLM/agent code execution with host broker gatekeeper.
- **`browser-probe`**: Passive Chromium/CDP inspection inside Firecracker.

---

## Security Rationale

While Cindermote's legacy namespace runner enforces strict `fail-closed` policies (blocking unprivileged namespace clone, net access, credential reads), process-level Linux container isolation shares the host kernel surface.

| Concern | Legacy Namespace Profile | Firecracker microVM Profile |
|---|---|---|
| **Boundary** | Shared Host Kernel (seccomp/ptrace) | Hardware Virtualization (KVM) |
| **Kernel Attack Surface** | Exposed syscalls subject to BPF filter | Isolated Guest Linux Kernel |
| **Evidence Blindness** | Host-observed syscall tracing | Cryptographically sealed HPKE envelopes |
| **Memory Isolation** | Shared host RAM (cgroups/mlock) | Dedicated VMM guest RAM |

---

## Migration Guide

### 1. Command-Line Detonations

**Old (Legacy Namespace):**
```bash
cindermote detonate /path/to/payload.py python-script
```

**New (Firecracker Agent-Probe):**
```bash
export CINDERMOTE_AGENT_PROBE_API_KEY_FD=3
export CINDERMOTE_AGENT_PROBE_ENDPOINT="https://api.openai.example.com/v1/chat/completions"
export CINDERMOTE_AGENT_PROBE_MODEL="gpt-4o"

cindermote detonate /path/to/target.skill agent-probe 3< /path/to/api_key.txt
```

### 2. Programmatic API

**Old:**
```python
from cindermote.mote.detonate import detonate

receipt = detonate("payload.py", "python-script")
```

**New:**
```python
from cindermote.agent_probe.runner import run_agent_probe
from cindermote.agent_probe.contract import ModelConfig

result = run_agent_probe(
    target_path="target.skill",
    model=ModelConfig("openai-compatible", "gpt-4o", "https://api.openai.example.com/v1/chat/completions"),
    api_key=bytearray(b"sk-..."),
)
```

---

## Current behavior and timeline

- **Today (1.0.x):** the legacy profile still works and is the engine behind the
  Cinder Incident Gate. `cindermote detonate <artifact> <legacy-type>` prints a
  deprecation notice on stderr. The other legacy entry points
  (`incident-gate`, `mote/detonate.py`, `detonate()`) do not.
- **As root** the runner now requires a writable cgroup v2 mount and is denied
  otherwise (cgroup v1 or hybrid hosts). **As a normal user** it runs in the
  explicit `degraded-user` mode without cgroups or mlock, and receipts record that.
- **Removal:** not scheduled. An earlier draft named v3.0, but no release numbering
  beyond 1.x exists. Removal will be announced in [CHANGELOG.md](../CHANGELOG.md) at
  least one minor release ahead. Firecracker execution is mandatory for agent-probe
  and browser-probe today.
