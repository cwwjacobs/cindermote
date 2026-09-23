"""Auto-discovery registry for probe modules under ``canaries/``.

Scans the ``canaries/`` directory for Python files, executes the exact source
bytes that were admitted, and finds each module's concrete ``ProbeBase``
subclass. This lets new probes be added by simply dropping a ``.py`` file — no
modifications to ``incident_gate.py``.
"""

from __future__ import annotations

import hashlib
import inspect
import sys
import types
from pathlib import Path
from typing import Type

from .probe_base import ProbeBase

CANARIES_DIR = Path(__file__).resolve().parent


class ProbeDiscoveryError(RuntimeError):
    """A declared probe artifact could not be faithfully materialized."""


def _read_artifact(path: Path) -> tuple[str, bytes]:
    """Return the resolved path text and the exact source bytes to execute."""
    try:
        resolved = path.resolve(strict=True)
        source = resolved.read_bytes()
    except OSError as exc:
        raise ProbeDiscoveryError(f"probe artifact is unreadable: {path}") from exc
    if not resolved.is_file():
        raise ProbeDiscoveryError(f"probe artifact is not a regular file: {path}")
    return str(resolved), source


def _artifact_module_name(path_text: str, source: bytes, stem: str) -> str:
    """Return a module name bound to probe location and admitted source bytes."""
    digest = hashlib.sha256(
        path_text.encode("utf-8", "surrogateescape") + b"\0" + source
    ).hexdigest()[:24]
    return f"canaries._discovered_{stem}_{digest}"


def _execute_artifact(path: Path) -> types.ModuleType:
    """Compile and execute exactly the bytes used to derive the module identity.

    Deliberately avoid SourceFileLoader here. Its timestamp/size-based ``.pyc``
    cache can execute stale bytecode after an in-place same-size source update.
    Reading once, hashing those bytes, and compiling those same bytes also closes
    the hash/execute TOCTOU window present when a loader re-opens the path.
    """
    path_text, source = _read_artifact(path)
    module_name = _artifact_module_name(path_text, source, path.stem)
    module = types.ModuleType(module_name)
    module.__file__ = path_text
    module.__package__ = "canaries"
    module.__loader__ = None
    sys.modules[module_name] = module
    try:
        code = compile(source, path_text, "exec", dont_inherit=True)
        exec(code, module.__dict__)
    except (Exception, SystemExit) as exc:
        sys.modules.pop(module_name, None)
        raise ProbeDiscoveryError(f"probe artifact import failed: {path}") from exc
    return module


def _module_probe_class(module: types.ModuleType, path: Path) -> Type[ProbeBase]:
    """Return the one concrete probe class defined by ``module`` itself."""
    classes: list[Type[ProbeBase]] = []
    for _, obj in inspect.getmembers(module, inspect.isclass):
        if (
            obj.__module__ == module.__name__
            and issubclass(obj, ProbeBase)
            and obj is not ProbeBase
            and not inspect.isabstract(obj)
        ):
            classes.append(obj)

    if len(classes) != 1:
        raise ProbeDiscoveryError(
            f"probe artifact must define exactly one concrete ProbeBase subclass: {path}"
        )
    return classes[0]


def discover_probes(
    directory: Path | None = None,
    *,
    exclude: set[str] | None = None,
) -> list[Type[ProbeBase]]:
    """Execute probe artifacts and return their concrete ProbeBase subclasses.

    Parameters
    ----------
    directory : Path, optional
        Directory to scan. Defaults to the ``canaries/`` package directory.
    exclude : set[str], optional
        Module basenames to skip (e.g. ``{"__init__", "probe_base", "registry"}``).

    Returns
    -------
    list[Type[ProbeBase]]
        Concrete probe classes, sorted by ``name`` for deterministic ordering.

    Raises
    ------
    ProbeDiscoveryError
        If an artifact cannot be read/executed, does not define exactly one
        concrete probe, or collides with another probe's declared name.
    """
    scan_dir = directory or CANARIES_DIR
    skip = exclude or {"__init__", "probe_base", "registry"}

    discovered: list[tuple[str, Type[ProbeBase]]] = []
    seen_names: dict[str, Path] = {}
    for path in sorted(scan_dir.glob("*.py")):
        stem = path.stem
        if stem in skip or stem.startswith("_"):
            continue

        module = _execute_artifact(path)
        probe_class = _module_probe_class(module, path)
        try:
            probe_name = probe_class().name
        except Exception as exc:
            raise ProbeDiscoveryError(f"probe artifact name evaluation failed: {path}") from exc
        if not isinstance(probe_name, str) or not probe_name:
            raise ProbeDiscoveryError(f"probe artifact declared an invalid name: {path}")
        prior = seen_names.get(probe_name)
        if prior is not None:
            raise ProbeDiscoveryError(
                f"duplicate probe name {probe_name!r}: {prior} and {path}"
            )
        seen_names[probe_name] = path
        discovered.append((probe_name, probe_class))

    discovered.sort(key=lambda item: item[0])
    return [probe_class for _, probe_class in discovered]


def instantiate_probes(
    directory: Path | None = None,
    *,
    names: set[str] | None = None,
) -> list[ProbeBase]:
    """Discover and instantiate probes, optionally filtering by name.

    Parameters
    ----------
    directory : Path, optional
        Directory to scan.
    names : set[str], optional
        If provided, only return probes whose ``name`` is in this set.

    Returns
    -------
    list[ProbeBase]
        Instantiated probe objects, sorted by name.
    """
    classes = discover_probes(directory)
    probes = [cls() for cls in classes]
    if names is not None:
        probes = [p for p in probes if p.name in names]
    return probes
