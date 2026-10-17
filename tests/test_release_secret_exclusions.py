"""Exercise release secret exclusions using only a synthetic source tree."""

from __future__ import annotations

import shlex
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "package-release.sh"
PACKAGE_NAME = "Cindermote_v1_clean"
ENV_EXCLUSIONS = (
    "  --exclude='.env' \\\n",
    "  --exclude='.env.*' \\\n",
    "  --exclude='*.env' \\\n",
)
SECRET_PATHS = {
    ".env",
    ".env.local",
    "openai.env",
    "config/.env",
    "config/.env.production",
    "config/provider.env",
}


def _package_synthetic_project(
    tmp_path: Path, *, remove_env_exclusions: bool = False
) -> dict[str, set[str]]:
    required = ("bash", "rsync", "find", "chmod", "tar", "zip", "sha256sum")
    missing = [command for command in required if shutil.which(command) is None]
    if missing:
        pytest.skip("release packaging utilities unavailable: " + ", ".join(missing))

    project = tmp_path / "synthetic-project"
    (project / "scripts").mkdir(parents=True)
    (project / "tests" / "fixtures").mkdir(parents=True)
    (project / "src").mkdir()
    (project / "src" / "safe.py").write_text("SAFE_SOURCE = True\n", encoding="utf-8")
    for relative in SECRET_PATHS:
        path = project / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("FAKE_CREDENTIAL=synthetic-test-only\n", encoding="utf-8")

    script_source = SCRIPT.read_text(encoding="utf-8")
    if remove_env_exclusions:
        for exclusion in ENV_EXCLUSIONS:
            assert exclusion in script_source
            script_source = script_source.replace(exclusion, "", 1)
    copied_script = project / "scripts" / SCRIPT.name
    copied_script.write_text(script_source, encoding="utf-8")
    result = subprocess.run(
        ["bash", str(copied_script)],
        cwd=project,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr

    with tarfile.open(project / "dist" / f"{PACKAGE_NAME}.tar.gz", "r:gz") as archive:
        tar_members = set(archive.getnames())
    with zipfile.ZipFile(project / "dist" / f"{PACKAGE_NAME}.zip") as archive:
        zip_members = set(archive.namelist())
    return {"tar": tar_members, "zip": zip_members}


def _assert_env_exclusions(archives: dict[str, set[str]]) -> None:
    for kind, members in archives.items():
        assert f"{PACKAGE_NAME}/src/safe.py" in members
        leaked = {path for path in SECRET_PATHS if f"{PACKAGE_NAME}/{path}" in members}
        assert not leaked, f"release archives contain {kind} secret paths: {sorted(leaked)}"


def test_release_rsync_arguments_explicitly_exclude_env_files() -> None:
    lines = SCRIPT.read_text(encoding="utf-8").splitlines(keepends=True)
    start = next(index for index, line in enumerate(lines) if line.lstrip().startswith("rsync "))
    command_lines = []
    for line in lines[start:]:
        command_lines.append(line)
        if not line.rstrip().endswith("\\"):
            break
    arguments = shlex.split("".join(command_lines).replace("\\\n", ""), comments=True)
    assert arguments[0] == "rsync"
    assert {"--exclude=.env", "--exclude=.env.*", "--exclude=*.env"} <= set(arguments[1:])


def test_release_archives_exclude_root_and_nested_env_files(tmp_path: Path) -> None:
    _assert_env_exclusions(_package_synthetic_project(tmp_path))


def test_release_secret_regression_detects_missing_exclusions(tmp_path: Path) -> None:
    archives = _package_synthetic_project(tmp_path, remove_env_exclusions=True)
    for members in archives.values():
        assert {f"{PACKAGE_NAME}/{path}" for path in SECRET_PATHS} <= members
    with pytest.raises(AssertionError, match="release archives contain"):
        _assert_env_exclusions(archives)
