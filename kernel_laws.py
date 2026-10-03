"""Cindermote Kernel Laws and registry verification.

The ten kernel laws:
1. Raw untrusted semantic output never enters the trusted host agent.
2. Every external capability is brokered, blocked, or absent.
3. Unknown capability requests collapse the kernel.
4. Operator and host-owned policy can initiate Burn at any time.
5. Collapse does not depend on guest cooperation.
6. Burn must produce purge evidence.
7. Replay remains sealed outside a quarantined viewer.
8. Missing evidence is failure, not success.
9. API-provider exposure is an explicit trust boundary.
10. Closure applies only to the declared reachable surface, never to the universe in general.

Most laws are runtime properties that other tests exercise. This module checks
the part that can be checked statically: the declared registries in ``docs/``
(seams, capabilities, collapse cues, field atlas) must parse, be internally
consistent, agree with the reference capability table, and only claim code that
exists. A registry that is missing or empty fails; it never passes vacuously.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_DOCS_DIR = REPO_ROOT / "docs"

TRUST_ZONES = frozenset({"TAINTED_GUEST", "BROKERED_SEAM", "TRUSTED_HOST", "QUARANTINE", "EXTERNAL_PROVIDER"})
ATLAS_STATUSES = frozenset({"implemented", "reference", "disabled", "removed"})
CAPABILITY_DISPOSITIONS = frozenset({"ALLOW", "DENY", "QUARANTINE", "COLLAPSE", "BROKERED", "PROHIBITED"})
CUE_ACTIONS = frozenset({"ALLOW", "DENY", "QUARANTINE", "COLLAPSE"})


@dataclass
class VerificationResult:
    valid: bool
    errors: List[str]
    summary: Dict[str, int] = field(default_factory=dict)


# --- markdown table parsing ----------------------------------------------------

_SEPARATOR_CELL = re.compile(r"^:?-{3,}:?$")


def _clean_cell(cell: str) -> str:
    return cell.strip().strip("*_").strip().strip("`").strip()


def _split_row(line: str) -> list[str]:
    inner = line.strip()
    if inner.startswith("|"):
        inner = inner[1:]
    if inner.endswith("|"):
        inner = inner[:-1]
    return [_clean_cell(cell) for cell in inner.split("|")]


def _is_separator(line: str) -> bool:
    return line.strip().startswith("|") and all(_SEPARATOR_CELL.match(cell) for cell in _split_row(line))


def parse_markdown_tables(text: str) -> list[list[dict[str, str]]]:
    """Return every GitHub-style table in ``text`` as a list of header-keyed rows."""

    lines = text.splitlines()
    tables: list[list[dict[str, str]]] = []
    index = 0
    while index < len(lines) - 1:
        if lines[index].strip().startswith("|") and _is_separator(lines[index + 1]):
            header = _split_row(lines[index])
            rows: list[dict[str, str]] = []
            index += 2
            while index < len(lines) and lines[index].strip().startswith("|"):
                cells = _split_row(lines[index])
                if len(cells) == len(header):
                    rows.append(dict(zip(header, cells)))
                index += 1
            tables.append(rows)
        else:
            index += 1
    return tables


def _load_table(docs_dir: Path, name: str, columns: set[str], errors: list[str]) -> list[dict[str, str]]:
    path = docs_dir / name
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        errors.append(f"{name}: registry cannot be read ({type(exc).__name__})")
        return []
    for table in parse_markdown_tables(text):
        if table and columns.issubset(table[0]):
            return table
    errors.append(f"{name}: no table with columns {sorted(columns)} and at least one row")
    return []


# --- validators ----------------------------------------------------------------


class KernelLawsValidator:
    def __init__(self, schemas_dir: Path | str | None = None) -> None:
        if schemas_dir is None:
            schemas_dir = REPO_ROOT / "schemas"
        self.schemas_dir = Path(schemas_dir)

    def validate_seams(self, seam_registry: Dict[str, Any]) -> VerificationResult:
        errors = []
        seams = seam_registry.get("seams", [])
        for seam in seams:
            if not seam.get("owner"):
                errors.append(f"Seam {seam.get('seam_id')} has no assigned owner.")
            if not seam.get("broker") and seam.get("source_zone") == "TAINTED_GUEST" and seam.get("target_zone") == "TRUSTED_HOST":
                errors.append(f"Unbrokered guest-to-host seam detected: {seam.get('seam_id')}")
        return VerificationResult(valid=len(errors) == 0, errors=errors)

    def validate_capabilities(self, capability_manifest: Dict[str, Any]) -> VerificationResult:
        errors = []
        capabilities = capability_manifest.get("capabilities", [])
        for cap in capabilities:
            disp = cap.get("disposition")
            if not disp or disp not in CAPABILITY_DISPOSITIONS:
                errors.append(f"Capability {cap.get('capability_id')} has invalid or missing disposition: {disp}")
            if disp == "BROKERED" and not cap.get("broker_required"):
                errors.append(f"Capability {cap.get('capability_id')} set to BROKERED but broker_required is False")
        return VerificationResult(valid=len(errors) == 0, errors=errors)

    def validate_collapse_cues(self, cue_registry: Dict[str, Any]) -> VerificationResult:
        errors = []
        cues = cue_registry.get("cues", [])
        for cue in cues:
            action = cue.get("terminal_action")
            if not action or action not in CUE_ACTIONS:
                errors.append(f"Collapse cue {cue.get('cue_id')} lacks valid terminal action: {action}")
        return VerificationResult(valid=len(errors) == 0, errors=errors)

    def validate_field_atlas(self, atlas: List[Dict[str, Any]], repo_root: Path = REPO_ROOT) -> VerificationResult:
        """Components may only claim code that exists; removed components must be gone."""

        errors = []
        for component in atlas:
            name = component.get("component")
            if component.get("trust_zone") not in TRUST_ZONES:
                errors.append(f"Component {name} has an unknown trust zone: {component.get('trust_zone')}")
            status = component.get("status")
            if status not in ATLAS_STATUSES:
                errors.append(f"Component {name} has an unknown status: {status}")
                continue
            paths = [part.strip().strip("`") for part in str(component.get("code", "")).split(",") if part.strip()]
            if status == "removed":
                for relative in paths:
                    if (repo_root / relative).exists():
                        errors.append(f"Component {name} is marked removed but {relative} still exists")
                continue
            if not paths:
                errors.append(f"Component {name} is marked {status} but names no code")
            for relative in paths:
                if not (repo_root / relative).exists():
                    errors.append(f"Component {name} is marked {status} but {relative} does not exist")
        return VerificationResult(valid=len(errors) == 0, errors=errors)


def _truthy(value: str) -> bool:
    return value.strip().lower() in {"yes", "true"}


def run_kernel_law_checks(
    docs_dir: Path | str | None = None,
    repo_root: Path | str | None = None,
) -> VerificationResult:
    """Validate the declared registries in ``docs/`` against the kernel laws."""

    docs = Path(docs_dir) if docs_dir is not None else DEFAULT_DOCS_DIR
    root = Path(repo_root) if repo_root is not None else REPO_ROOT
    validator = KernelLawsValidator()
    errors: list[str] = []

    seam_rows = _load_table(
        docs, "SEAM_REGISTRY.md", {"Seam ID", "Source Zone", "Target Zone", "Owner", "Broker", "Instrumented"}, errors
    )
    seams = [
        {
            "seam_id": row["Seam ID"],
            "source_zone": row["Source Zone"],
            "target_zone": row["Target Zone"],
            "owner": row["Owner"],
            "broker": "" if row["Broker"].lower().startswith("none") else row["Broker"],
            "instrumented": _truthy(row["Instrumented"]),
        }
        for row in seam_rows
    ]
    errors.extend(validator.validate_seams({"seams": seams}).errors)
    for seam in seams:
        if not seam["instrumented"]:
            errors.append(f"Seam {seam['seam_id']} is not instrumented")
        for zone_name in ("source_zone", "target_zone"):
            if seam[zone_name] not in TRUST_ZONES:
                errors.append(f"Seam {seam['seam_id']} has an unknown {zone_name}: {seam[zone_name]}")

    capability_rows = _load_table(
        docs, "CAPABILITY_MANIFEST.md", {"Capability", "Component", "Broker Required", "Default Disposition"}, errors
    )
    capabilities: list[dict[str, Any]] = [
        {
            "capability_id": "unknown_capability" if "unknown capability" in row["Capability"].lower() else row["Capability"],
            "component_id": row["Component"],
            "disposition": row["Default Disposition"],
            "broker_required": _truthy(row["Broker Required"]),
        }
        for row in capability_rows
    ]
    errors.extend(validator.validate_capabilities({"capabilities": capabilities}).errors)
    if capabilities:
        for capability in capabilities:
            if not capability["broker_required"]:
                errors.append(f"Law 2: capability {capability['capability_id']} does not require a broker")
        unknown = [c for c in capabilities if c["capability_id"] == "unknown_capability"]
        if not unknown or any(c["disposition"] != "COLLAPSE" for c in unknown):
            errors.append("Law 3: the manifest must declare unknown capabilities as COLLAPSE")
        # The manifest and the reference decision table must agree.
        from capability_brokers import CapabilityBroker

        declared = CapabilityBroker().declared_capabilities
        documented = {c["capability_id"]: c["disposition"] for c in capabilities if c["capability_id"] != "unknown_capability"}
        for name in sorted(set(declared) | set(documented)):
            if declared.get(name) != documented.get(name):
                errors.append(
                    f"Capability {name}: manifest says {documented.get(name)}, "
                    f"capability_brokers.py says {declared.get(name)}"
                )

    cue_rows = _load_table(docs, "COLLAPSE_CUES.md", {"Trigger Condition", "Cue ID", "Required Action"}, errors)
    cues = [
        {"cue_id": row["Cue ID"], "trigger_condition": row["Trigger Condition"], "terminal_action": row["Required Action"]}
        for row in cue_rows
    ]
    errors.extend(validator.validate_collapse_cues({"cues": cues}).errors)
    if cues and not any(c["cue_id"] == "unknown_capability_request" and c["terminal_action"] == "COLLAPSE" for c in cues):
        errors.append("Law 3: COLLAPSE_CUES.md must declare unknown_capability_request as COLLAPSE")

    atlas_rows = _load_table(docs, "FIELD_ATLAS.md", {"Component", "Trust Zone", "Status", "Code", "Description"}, errors)
    atlas = [
        {
            "component": row["Component"],
            "trust_zone": row["Trust Zone"],
            "status": row["Status"],
            "code": row["Code"],
        }
        for row in atlas_rows
    ]
    errors.extend(validator.validate_field_atlas(atlas, root).errors)

    summary = {"seams": len(seams), "capabilities": len(capabilities), "cues": len(cues), "components": len(atlas)}
    return VerificationResult(valid=not errors, errors=errors, summary=summary)
