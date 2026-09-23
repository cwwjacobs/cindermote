"""Tests for the canaries pluggable probe framework and registry."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

THIS_FILE = Path(__file__).resolve()
PROJECT_DIR = THIS_FILE.parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from canaries.probe_base import ProbeBase, ProbeExpectation
from canaries.registry import discover_probes, instantiate_probes
from incident_gate import CINDER_PROBES, load_discovered_probes


def test_discover_probes_returns_probe_classes():
    """discover_probes() discovers concrete ProbeBase subclasses."""
    classes = discover_probes()
    assert len(classes) >= 7
    for cls in classes:
        assert issubclass(cls, ProbeBase)


def test_instantiate_probes_lifecycle():
    """instantiate_probes() instantiates valid probes with expected fields."""
    probes = instantiate_probes()
    assert len(probes) >= 7
    names = [p.name for p in probes]
    assert "benign_baseline" in names
    assert "credential_harvest" in names
    assert "lateral_movement" in names

    for p in probes:
        assert isinstance(p.name, str) and len(p.name) > 0
        assert isinstance(p.description, str) and len(p.description) > 0
        assert isinstance(p.source, str) and len(p.source) > 0
        exp = p.expectation
        assert isinstance(exp, ProbeExpectation)
        assert exp.risk in {"hostile", "suspicious", "benign"}
        assert exp.decision in {"ALLOW", "DENY"}
        assert isinstance(exp.rules, frozenset)


def test_instantiate_probes_name_filtering():
    """instantiate_probes(names=...) filters probes by name."""
    selected = instantiate_probes(names={"benign_baseline", "metadata_access"})
    assert len(selected) == 2
    names = {p.name for p in selected}
    assert names == {"benign_baseline", "metadata_access"}


def test_discovery_is_repeatable_and_unique():
    """Repeated discovery must preserve ordering and must not duplicate probes."""
    first = [p.name for p in instantiate_probes()]
    second = [p.name for p in instantiate_probes()]
    assert first == second
    assert len(first) == len(set(first))


def test_incident_gate_dynamic_probes():
    """incident_gate.CINDER_PROBES is dynamically populated from the registry."""
    cinder_probes = load_discovered_probes()
    names = [p.name for p in cinder_probes]
    assert names == [
        "registry_proxy_abuse",
        "lateral_movement",
        "metadata_access",
        "credential_harvest",
        "outbound_exfil",
        "tainted_output",
    ]
    assert "benign_baseline" not in names


def test_dynamic_probe_file_discovery():
    """Adding a new probe file dynamically registers it without incident_gate changes."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        probe_code = '''\
from canaries.probe_base import ProbeBase, ProbeExpectation

class DynamicTestProbe(ProbeBase):
    @property
    def name(self) -> str: return "dynamic_test"
    @property
    def description(self) -> str: return "Dynamic test probe"
    @property
    def source(self) -> str: return "print('dynamic')"
    @property
    def expectation(self) -> ProbeExpectation:
        return ProbeExpectation(risk="benign", decision="ALLOW")
'''
        (tmp_path / "probe_dynamic_test.py").write_text(probe_code)
        discovered = discover_probes(tmp_path)
        assert len(discovered) == 1
        probe_instance = discovered[0]()
        assert probe_instance.name == "dynamic_test"
        assert probe_instance.expectation.decision == "ALLOW"


def test_discovery_does_not_reuse_same_stem_from_prior_artifact():
    """Later bytes must not inherit a stale module from an earlier artifact."""
    template = '''\
from canaries.probe_base import ProbeBase, ProbeExpectation

class {class_name}(ProbeBase):
    @property
    def name(self) -> str: return "{probe_name}"
    @property
    def description(self) -> str: return "cache-boundary probe"
    @property
    def source(self) -> str: return "print('{probe_name}')"
    @property
    def expectation(self) -> ProbeExpectation:
        return ProbeExpectation(risk="benign", decision="ALLOW")
'''
    try:
        with tempfile.TemporaryDirectory() as first_tmp, tempfile.TemporaryDirectory() as second_tmp:
            first_dir = Path(first_tmp)
            second_dir = Path(second_tmp)
            first_path = first_dir / "probe_cache_boundary.py"
            second_path = second_dir / "probe_cache_boundary.py"
            first_path.write_text(
                template.format(class_name="FirstProbe", probe_name="first_artifact"),
                encoding="utf-8",
            )
            second_path.write_text(
                template.format(class_name="SecondProbe", probe_name="second_artifact"),
                encoding="utf-8",
            )

            first = discover_probes(first_dir)
            second = discover_probes(second_dir)

            assert [cls().name for cls in first] == ["first_artifact"]
            assert [cls().name for cls in second] == ["second_artifact"]

            first_path.write_text(
                template.format(class_name="ThirdProbe", probe_name="third_artifact"),
                encoding="utf-8",
            )
            third = discover_probes(first_dir)
            assert [cls().name for cls in third] == ["third_artifact"]
    finally:
        for name in list(sys.modules):
            if "probe_cache_boundary" in name and name.startswith("canaries."):
                sys.modules.pop(name, None)


def test_broken_probe_artifact_fails_discovery():
    """A declared probe artifact may not disappear silently when import fails."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "probe_broken.py"
        path.write_text("def this is not valid python", encoding="utf-8")
        with pytest.raises(RuntimeError, match="probe artifact"):
            discover_probes(Path(tmpdir))


def test_duplicate_probe_names_fail_closed():
    """Two artifacts may not claim the same probe identity."""
    template = '''\\
from canaries.probe_base import ProbeBase, ProbeExpectation

class {class_name}(ProbeBase):
    @property
    def name(self) -> str: return "duplicate_name"
    @property
    def description(self) -> str: return "duplicate identity test"
    @property
    def source(self) -> str: return "print('duplicate')"
    @property
    def expectation(self) -> ProbeExpectation:
        return ProbeExpectation(risk="hostile", decision="DENY")
'''
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "probe_one.py").write_text(
            template.format(class_name="FirstDuplicate"), encoding="utf-8"
        )
        (root / "probe_two.py").write_text(
            template.format(class_name="SecondDuplicate"), encoding="utf-8"
        )
        with pytest.raises(RuntimeError, match="duplicate probe name"):
            discover_probes(root)


def test_probe_artifact_must_define_exactly_one_concrete_probe():
    """Ambiguous artifacts with multiple local probe classes fail closed."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "probe_ambiguous.py"
        path.write_text(
            '''\\
from canaries.probe_base import ProbeBase, ProbeExpectation

class FirstProbe(ProbeBase):
    @property
    def name(self): return "first"
    @property
    def description(self): return "first"
    @property
    def source(self): return "print(1)"
    @property
    def expectation(self): return ProbeExpectation("hostile", "DENY")

class SecondProbe(ProbeBase):
    @property
    def name(self): return "second"
    @property
    def description(self): return "second"
    @property
    def source(self): return "print(2)"
    @property
    def expectation(self): return ProbeExpectation("hostile", "DENY")
''',
            encoding="utf-8",
        )
        with pytest.raises(RuntimeError, match="exactly one concrete ProbeBase"):
            discover_probes(Path(tmpdir))


def test_imported_probe_class_does_not_count_as_local_definition():
    """Only classes defined by the artifact itself participate in discovery."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "probe_local.py"
        path.write_text(
            '''\\
from canaries.probe_benign_baseline import BenignBaselineProbe
from canaries.probe_base import ProbeBase, ProbeExpectation

class LocalProbe(ProbeBase):
    @property
    def name(self): return "local_only"
    @property
    def description(self): return "local"
    @property
    def source(self): return "print('local')"
    @property
    def expectation(self): return ProbeExpectation("benign", "ALLOW")
''',
            encoding="utf-8",
        )
        discovered = discover_probes(Path(tmpdir))
        assert [cls().name for cls in discovered] == ["local_only"]


def test_discovery_works_in_fresh_interpreter_without_import_order_help():
    """Registry discovery must not depend on another module preloading import helpers."""
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "from canaries.registry import discover_probes; "
            "print(len(discover_probes()))",
        ],
        cwd=PROJECT_DIR,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert int(completed.stdout.strip()) >= 7


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
