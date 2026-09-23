#!/usr/bin/env python3
"""Real KVM/Firecracker competition gate against a controlled HTTPS fixture."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import ssl
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


PROJECT_DIR = Path(__file__).resolve().parents[2]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from cindermote.mote.browser_contract import (  # noqa: E402
    TELEMETRY_INCOMPLETE_FINDINGS,
    make_probe_request,
    normalize_origin,
    reduce_browser_evidence,
    validate_browser_evidence,
)
from cindermote.mote.detonate import (  # noqa: E402
    OBSERVER_KEY_PATH,
    RECEIPTS_DIR,
    detonate_browser_probe,
)
from cindermote.mote.firecracker_runtime import (  # noqa: E402
    DEFAULT_CACHE_DIR,
    DEFAULT_CGROUP_ROOT,
    DEFAULT_RUNTIME_ROOT,
    _owned_stale_job_tokens,
    preflight_firecracker,
)
from cindermote.observer.receipt import (  # noqa: E402
    load_or_create_key,
    sha256_file,
    sign_receipt,
    validate_receipt,
    verify_signature,
)


TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
CASES = (
    ("clean", "/case/clean", None),
    ("post", "/case/post", "web_active_interaction_attempt"),
    ("websocket", "/case/websocket", "web_active_interaction_attempt"),
    ("popup", "/case/popup", "web_popup_attempt"),
    ("unauthorized", "/case/unauthorized", "web_unauthorized_origin_attempt"),
)
SOURCE_SCOPES = (
    ".dockerignore",
    "broker",
    "gate",
    "guest",
    "images/firecracker",
    "mote",
    "cindermote",
    "observer",
    "policy",
    "schemas",
    "scripts",
    "tests/firecracker",
)
DERIVED_SOURCE_PARTS = frozenset(
    {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
)
DERIVED_SOURCE_SUFFIXES = frozenset({".pyc", ".pyo"})
FIXTURE_SOURCE_PATHS = ("tests/firecracker/fixture_https_server.py",)
POLICY_PATH = "policy/hotcell-policy.json"
ASSET_LOCK_PATH = "policy/firecracker-assets.lock.json"
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
GIT_COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40,64}$")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _project_path(project_dir: Path, relative_path: str) -> Path:
    relative = Path(relative_path)
    if not relative_path or relative.is_absolute() or ".." in relative.parts:
        raise AssertionError("provenance path must be project-relative")
    project = project_dir.resolve(strict=True)
    candidate = project / relative
    try:
        candidate.resolve(strict=False).relative_to(project)
    except (OSError, ValueError) as exc:
        raise AssertionError("provenance path escapes the project") from exc
    return candidate


def _file_record(project_dir: Path, relative_path: str) -> dict[str, Any]:
    """Hash one non-symlink file while rejecting a concurrent rewrite."""

    path = _project_path(project_dir, relative_path)
    return _path_record(path, relative_path)


def _path_record(path: Path, recorded_path: str) -> dict[str, Any]:
    """Hash a named path while rejecting symlinks and concurrent rewrites."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AssertionError(f"provenance file is unavailable: {recorded_path}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise AssertionError(f"provenance path is not a regular file: {recorded_path}")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        current = path.lstat()
    except OSError as exc:
        raise AssertionError(f"provenance file disappeared: {recorded_path}") from exc
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    identity_current = (
        current.st_dev,
        current.st_ino,
        current.st_mode,
        current.st_size,
        current.st_mtime_ns,
        current.st_ctime_ns,
    )
    if identity_before != identity_after or identity_after != identity_current:
        raise AssertionError(f"provenance file changed while hashing: {recorded_path}")
    return {
        "path": recorded_path,
        "sha256": digest.hexdigest(),
        "size_bytes": before.st_size,
        "mode": f"{stat.S_IMODE(before.st_mode):04o}",
    }


def _source_paths(project_dir: Path, scopes: tuple[str, ...]) -> list[str]:
    paths: set[str] = set()
    project = project_dir.resolve(strict=True)
    for scope in scopes:
        root = _project_path(project, scope)
        try:
            metadata = root.lstat()
        except OSError as exc:
            raise AssertionError(f"source scope is unavailable: {scope}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise AssertionError(f"source scope is a symlink: {scope}")
        if not stat.S_ISREG(metadata.st_mode) and not stat.S_ISDIR(metadata.st_mode):
            raise AssertionError(f"source scope is not a regular file or directory: {scope}")
        candidates = [root] if stat.S_ISREG(metadata.st_mode) else root.rglob("*")
        for candidate in candidates:
            relative = candidate.relative_to(project)
            if any(part in DERIVED_SOURCE_PARTS for part in relative.parts):
                continue
            if candidate.suffix in DERIVED_SOURCE_SUFFIXES:
                continue
            try:
                candidate_metadata = candidate.lstat()
            except OSError as exc:
                raise AssertionError(f"source path disappeared: {relative.as_posix()}") from exc
            if stat.S_ISLNK(candidate_metadata.st_mode):
                raise AssertionError(f"source scope contains a symlink: {relative.as_posix()}")
            if stat.S_ISREG(candidate_metadata.st_mode):
                paths.add(relative.as_posix())
            elif not stat.S_ISDIR(candidate_metadata.st_mode):
                raise AssertionError(f"source scope contains a special file: {relative.as_posix()}")
    return sorted(paths)


def _source_snapshot(project_dir: Path, scopes: tuple[str, ...]) -> dict[str, Any]:
    files = [_file_record(project_dir, path) for path in _source_paths(project_dir, scopes)]
    manifest = {"scope": list(scopes), "files": files}
    return {**manifest, "manifest_sha256": hashlib.sha256(_canonical_json(manifest)).hexdigest()}


def _git_head(project_dir: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(project_dir), "rev-parse", "--verify", "HEAD^{commit}"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AssertionError("cannot resolve the gate source Git HEAD") from exc
    value = result.stdout.strip().lower()
    if GIT_COMMIT_PATTERN.fullmatch(value) is None:
        raise AssertionError("gate source Git HEAD is malformed")
    return value


def collect_gate_provenance(
    project_dir: Path = PROJECT_DIR,
    *,
    source_scopes: tuple[str, ...] = SOURCE_SCOPES,
    fixture_sources: tuple[str, ...] = FIXTURE_SOURCE_PATHS,
    policy_path: str = POLICY_PATH,
    asset_lock_path: str = ASSET_LOCK_PATH,
    cache_dir: Path = DEFAULT_CACHE_DIR,
) -> dict[str, Any]:
    """Collect a re-verifiable content identity for one supported-host run."""

    source_snapshot = _source_snapshot(project_dir, source_scopes)
    fixture_records = [_file_record(project_dir, path) for path in fixture_sources]
    policy_record = _file_record(project_dir, policy_path)
    asset_lock_record = _file_record(project_dir, asset_lock_path)
    asset_lock = _strict_json_file(_project_path(project_dir, asset_lock_path), 1024 * 1024)
    if _file_record(project_dir, asset_lock_path) != asset_lock_record:
        raise AssertionError("asset lock changed while collecting provenance")
    try:
        rootfs_config = asset_lock["browser_rootfs"]
        rootfs_path = rootfs_config["path"]
        locked_rootfs_sha256 = rootfs_config["sha256"]
        receipt_path = rootfs_config["build_receipt_path"]
        locked_receipt_sha256 = rootfs_config["build_receipt_sha256"]
        receipt_schema = rootfs_config["required_receipt_schema"]
    except (KeyError, TypeError) as exc:
        raise AssertionError("asset lock lacks the browser rootfs provenance contract") from exc
    if not all(
        isinstance(value, str) and value
        for value in (
            rootfs_path,
            locked_rootfs_sha256,
            receipt_path,
            locked_receipt_sha256,
            receipt_schema,
        )
    ):
        raise AssertionError("asset lock browser rootfs provenance values are malformed")
    if (
        SHA256_PATTERN.fullmatch(locked_rootfs_sha256) is None
        or SHA256_PATTERN.fullmatch(locked_receipt_sha256) is None
    ):
        raise AssertionError("asset lock browser rootfs digests are malformed")
    cache = cache_dir.resolve(strict=True)
    rootfs_relative = Path(rootfs_path)
    receipt_relative = Path(receipt_path)
    if (
        rootfs_relative.is_absolute()
        or receipt_relative.is_absolute()
        or ".." in rootfs_relative.parts
        or ".." in receipt_relative.parts
    ):
        raise AssertionError("asset lock browser rootfs paths must be cache-relative")
    rootfs_artifact = cache / rootfs_relative
    receipt_artifact = cache / receipt_relative
    rootfs_record = _path_record(rootfs_artifact, rootfs_relative.as_posix())
    build_receipt_record = _path_record(receipt_artifact, receipt_relative.as_posix())
    build_receipt = _strict_json_file(receipt_artifact, 1024 * 1024)
    if _path_record(receipt_artifact, receipt_relative.as_posix()) != build_receipt_record:
        raise AssertionError("browser rootfs build receipt changed while collecting provenance")
    try:
        declared_schema = build_receipt["schema_version"]
        declared_rootfs_sha256 = build_receipt["rootfs"]["sha256"]
    except (KeyError, TypeError) as exc:
        raise AssertionError("browser rootfs build receipt lacks its digest binding") from exc
    if declared_schema != receipt_schema:
        raise AssertionError("browser rootfs build receipt schema differs from the asset lock")
    if (
        not isinstance(declared_rootfs_sha256, str)
        or SHA256_PATTERN.fullmatch(declared_rootfs_sha256) is None
    ):
        raise AssertionError("browser rootfs build receipt digest is malformed")
    if build_receipt_record["sha256"] != locked_receipt_sha256:
        raise AssertionError("browser rootfs build receipt differs from the asset lock")
    if (
        rootfs_record["sha256"] != declared_rootfs_sha256
        or rootfs_record["sha256"] != locked_rootfs_sha256
    ):
        raise AssertionError("browser rootfs differs from its build receipt or asset lock")
    return {
        "schema_version": "cindermote.firecracker-e2e-provenance/v1",
        "git_head": _git_head(project_dir),
        "source_snapshot": source_snapshot,
        "fixture_sources": fixture_records,
        "policy": policy_record,
        "asset_lock": asset_lock_record,
        "browser_rootfs": {
            "cache_root": str(cache),
            **rootfs_record,
            "lock_declared_sha256": locked_rootfs_sha256,
            "build_receipt": {
                **build_receipt_record,
                "lock_declared_sha256": locked_receipt_sha256,
                "schema_version": declared_schema,
                "declared_rootfs_sha256": declared_rootfs_sha256,
            },
        },
    }


def verify_gate_provenance(
    expected: dict[str, Any],
    project_dir: Path = PROJECT_DIR,
    **options: Any,
) -> None:
    """Fail unless checkout and artifact bytes still match a recorded identity."""

    observed = collect_gate_provenance(project_dir, **options)
    if observed != expected:
        raise AssertionError("gate provenance changed during or after collection")


def case_request(origin: str, path: str) -> dict[str, Any]:
    """Build the exact request used by the supported-host suite."""

    return make_probe_request(origin + path)


def _read_private_token(path: Path) -> str:
    metadata = path.stat()
    if not path.is_file() or metadata.st_mode & 0o077:
        raise RuntimeError("fixture control token file must be private")
    token = path.read_text(encoding="ascii").strip()
    if TOKEN_PATTERN.fullmatch(token) is None:
        raise RuntimeError("fixture control token is malformed")
    return token


def _fixture_json(origin: str, path: str, token: str, *, method: str = "GET") -> dict:
    request = urllib.request.Request(
        origin + path,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "User-Agent": "cindermote-firecracker-e2e/1",
        },
        data=b"" if method == "POST" else None,
    )
    context = ssl.create_default_context()
    try:
        with urllib.request.urlopen(request, timeout=10, context=context) as response:
            body = response.read(64 * 1024 + 1)
    except (OSError, urllib.error.URLError) as exc:
        raise RuntimeError("controlled HTTPS fixture is unavailable") from exc
    if len(body) > 64 * 1024:
        raise RuntimeError("controlled HTTPS fixture response is excessive")
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("controlled HTTPS fixture returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise RuntimeError("controlled HTTPS fixture response is not an object")
    return value


def _write_private_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    payload = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(descriptor, payload.encode("ascii"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)


def _strict_json_file(path: Path, maximum: int) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise AssertionError("gate artifact is missing") from exc
    if not path.is_file() or path.is_symlink() or not 1 <= metadata.st_size <= maximum:
        raise AssertionError("gate artifact has unsafe metadata")
    raw = path.read_bytes()

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def constant(_value: str) -> None:
        raise ValueError("non-finite JSON number")

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_constant=constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise AssertionError("gate artifact is not strict JSON") from exc
    if not isinstance(value, dict):
        raise AssertionError("gate artifact must be a JSON object")
    return value


def _assert_clean_teardown(job_id: str) -> None:
    token = job_id.rsplit("-", 1)[-1]
    if token in _owned_stale_job_tokens(DEFAULT_RUNTIME_ROOT, DEFAULT_CGROUP_ROOT):
        raise AssertionError("owned Firecracker resources remain after signed purge")


def _verify_probe_receipt(
    receipt: dict,
    request: dict[str, Any],
    expected_finding: str | None,
) -> dict[str, Any]:
    validate_receipt(receipt)
    key = Path(OBSERVER_KEY_PATH).read_bytes()
    if len(key) != 32 or not verify_signature(receipt, key):
        raise AssertionError("browser receipt signature did not verify")
    browser = receipt["browser_probe"]
    findings = {item["finding_id"] for item in browser["findings"]}
    reduction = browser["reduction"]
    if (
        reduction.get("complete") is not True
        or reduction.get("telemetry_incomplete") is not False
        or reduction.get("fail_closed") is not False
        or receipt.get("telemetry_incomplete") is not False
        or findings.intersection(TELEMETRY_INCOMPLETE_FINDINGS)
    ):
        raise AssertionError(
            "browser case has incomplete infrastructure or telemetry evidence"
        )
    expected_decision = "ALLOW" if expected_finding is None else "DENY"
    if receipt["gate"]["final_decision"] != expected_decision:
        raise AssertionError("browser case produced an unexpected gate decision")
    if expected_finding is None and findings:
        raise AssertionError("clean fixture case produced browser findings")
    if expected_finding is not None and expected_finding not in findings:
        raise AssertionError("adversarial fixture case missed its required finding")
    if browser["runtime"].get("admitted") is not True:
        raise AssertionError("browser case was not admitted to Firecracker")
    if browser["artifacts"].get("attestation_complete") is not True:
        raise AssertionError("browser case lacks sandboxed metadata attestation")
    purge = receipt["purge"]
    if purge.get("verified_externally") is not True or not all(
        value for name, value in purge.items() if name != "verified_externally"
    ):
        raise AssertionError("browser case did not prove complete teardown")
    job_id = receipt["identity"]["job_id"]
    _assert_clean_teardown(job_id)
    receipt_path = RECEIPTS_DIR / f"{job_id}.json"
    persisted = _strict_json_file(receipt_path, 8 * 1024 * 1024)
    if persisted != receipt or not verify_signature(persisted, key):
        raise AssertionError("persisted browser receipt differs or has an invalid signature")
    evidence_path = RECEIPTS_DIR / f"{job_id}.browser-evidence.json"
    if sha256_file(evidence_path) != browser["evidence"]["sha256"]:
        raise AssertionError("persisted browser evidence differs from its signed commitment")
    persisted_evidence = validate_browser_evidence(
        _strict_json_file(evidence_path, 32 * 1024 * 1024)
    )
    if reduce_browser_evidence(persisted_evidence, request) != browser["reduction"]:
        raise AssertionError("persisted evidence does not reproduce the signed reduction")
    return {
        "job_id": job_id,
        "decision": expected_decision,
        "finding_ids": sorted(findings),
        "receipt_sha256": sha256_file(receipt_path),
        "evidence_sha256": browser["evidence"]["sha256"],
        "firecracker_sha256": browser["runtime"]["firecracker_sha256"],
        "kernel_sha256": browser["runtime"]["kernel_sha256"],
        "rootfs_sha256": browser["runtime"]["rootfs_sha256"],
        "rootfs_receipt_sha256": browser["runtime"]["rootfs_receipt_sha256"],
        "browser_sha256": browser["runtime"]["browser_sha256"],
        "purge": purge,
    }


def run_gate(
    *,
    origin: str,
    unauthorized_origin: str,
    token_file: Path,
    output_path: Path,
) -> dict[str, Any]:
    # A failed rerun must never leave an older PASS artifact looking current.
    # Remove the prior name before even validating invocation inputs; all
    # failure paths then leave either no gate artifact or a newly signed FAIL.
    try:
        output_path.unlink(missing_ok=True)
    except OSError as exc:
        raise RuntimeError("cannot invalidate the previous gate artifact") from exc
    if os.path.lexists(output_path):
        raise RuntimeError("previous gate artifact still exists after invalidation")
    if os.geteuid() != 0:
        raise RuntimeError("the supported-host Firecracker gate must run as root")
    primary = normalize_origin(origin)
    secondary = normalize_origin(unauthorized_origin)
    if not primary.startswith("https://") or not secondary.startswith("https://"):
        raise RuntimeError("the competition fixture requires HTTPS origins")
    if primary == secondary:
        raise RuntimeError("the unauthorized fixture origin must be distinct")
    token = _read_private_token(token_file)
    observer_key = load_or_create_key(OBSERVER_KEY_PATH)
    provenance_start: dict[str, Any] | None = None
    summary: dict[str, Any] = {
        "schema_version": "cindermote.firecracker-e2e-gate/v2",
        "status": "RUNNING",
        "started_at_unix": int(time.time()),
        "working_directory": str(PROJECT_DIR),
        "host_kernel": os.uname().release,
        "fixture": {
            "primary_origin": primary,
            "unauthorized_origin": secondary,
            "control_token_recorded": False,
            "source_hash_verified_by_both_origins": False,
        },
        "command": (
            "sudo /usr/bin/python3 tests/firecracker/e2e_supported_host.py "
            "--origin <controlled-https-origin> --unauthorized-origin "
            "<controlled-secondary-origin> --control-token-file <private-file>"
        ),
        "cases": [],
        "local_authentication": {
            "algorithm": "HMAC-SHA256",
            "key_identifier_sha256": hashlib.sha256(observer_key).hexdigest(),
            "verification_scope": "local observer-key holder only",
            "externally_verifiable": False,
        },
    }
    try:
        provenance_start = collect_gate_provenance()
        summary["provenance"] = provenance_start
        preflight = preflight_firecracker(profile="browser")
        summary["preflight"] = preflight.to_dict()
        if not preflight.ready:
            raise RuntimeError("Firecracker supported-host preflight is not ready")
        expected_info = {
            "schema_version": "cindermote.e2e-fixture/v1",
            "primary_origin": primary,
            "unauthorized_origin": secondary,
            "fixture_source_sha256": {
                item["path"]: item["sha256"] for item in provenance_start["fixture_sources"]
            }[FIXTURE_SOURCE_PATHS[0]],
        }
        for fixture_origin in (primary, secondary):
            if _fixture_json(fixture_origin, "/control/info", token) != expected_info:
                raise RuntimeError("controlled HTTPS fixture identity check failed")
            if _fixture_json(fixture_origin, "/control/reset", token, method="POST") != {"reset": True}:
                raise RuntimeError("controlled HTTPS fixture reset failed")
        summary["fixture"]["source_hash_verified_by_both_origins"] = True

        for case_name, path, expected_finding in CASES:
            request = case_request(primary, path)
            receipt = detonate_browser_probe(request, submitted_by="competition-e2e")
            case_receipt = _verify_probe_receipt(receipt, request, expected_finding)
            if (
                case_receipt["rootfs_sha256"]
                != provenance_start["browser_rootfs"]["sha256"]
                or case_receipt["rootfs_receipt_sha256"]
                != provenance_start["browser_rootfs"]["build_receipt"]["sha256"]
            ):
                raise AssertionError(
                    "signed browser case differs from the gate-pinned rootfs provenance"
                )
            case_receipt["case"] = case_name
            summary["cases"].append(case_receipt)

        expected_fixture = {
            "schema_version": "cindermote.e2e-fixture/v1",
            "counts": {"post": 0, "websocket": 0, "popup": 0, "unauthorized": 0},
        }
        fixture_counts: dict[str, dict[str, int]] = {}
        for label, fixture_origin in (("primary", primary), ("secondary", secondary)):
            fixture = _fixture_json(fixture_origin, "/control/counts", token)
            if fixture != expected_fixture:
                raise AssertionError("a forbidden browser action reached the controlled fixture")
            fixture_counts[label] = fixture["counts"]
        summary["fixture_counts"] = fixture_counts
        postflight = preflight_firecracker(profile="browser")
        summary["postflight"] = postflight.to_dict()
        if not postflight.ready:
            raise AssertionError("Firecracker host failed post-run admission checks")
        if _owned_stale_job_tokens(DEFAULT_RUNTIME_ROOT, DEFAULT_CGROUP_ROOT):
            raise AssertionError("owned Firecracker resources remain after the suite")
        summary["status"] = "PASS"
        return summary
    except BaseException as exc:
        summary["status"] = "FAIL"
        summary["failure_type"] = type(exc).__name__
        summary["failure"] = str(exc)[:512]
        raise
    finally:
        provenance_failure: AssertionError | None = None
        active_failure = sys.exc_info()[0] is not None
        if provenance_start is None:
            summary["provenance_verification"] = {
                "status": "FAIL",
                "detail": "initial provenance collection did not complete",
            }
        else:
            try:
                verify_gate_provenance(provenance_start)
            except BaseException as exc:
                detail = str(exc)[:512] or type(exc).__name__
                summary["provenance_verification"] = {"status": "FAIL", "detail": detail}
                summary["status"] = "FAIL"
                if not active_failure:
                    summary["failure_type"] = "ProvenanceMutationError"
                    summary["failure"] = detail
                    provenance_failure = AssertionError(
                        "supported-host gate provenance changed during the run"
                    )
            else:
                summary["provenance_verification"] = {
                    "status": "PASS",
                    "detail": "checkout and artifact bytes match the recorded provenance",
                }
        summary["completed_at_unix"] = int(time.time())
        summary["receipt_signature"] = sign_receipt(summary, observer_key)
        _write_private_json(output_path, summary)
        persisted_summary = _strict_json_file(output_path, 8 * 1024 * 1024)
        if persisted_summary != summary or not verify_signature(persisted_summary, observer_key):
            raise AssertionError("persisted competition gate receipt did not verify")
        if provenance_failure is not None:
            raise provenance_failure


def verify_gate_result(output_path: Path) -> dict[str, Any]:
    """Re-verify a persisted PASS against current source, assets, and cases."""

    summary = _strict_json_file(output_path, 8 * 1024 * 1024)
    key = Path(OBSERVER_KEY_PATH).read_bytes()
    if len(key) != 32 or not verify_signature(summary, key):
        raise AssertionError("competition gate artifact signature is invalid")
    if (
        summary.get("schema_version") != "cindermote.firecracker-e2e-gate/v2"
        or summary.get("status") != "PASS"
        or summary.get("provenance_verification", {}).get("status") != "PASS"
        or summary.get("local_authentication", {}).get("externally_verifiable")
        is not False
    ):
        raise AssertionError("competition gate artifact is not a valid local PASS")
    provenance = summary.get("provenance")
    if not isinstance(provenance, dict):
        raise AssertionError("competition gate provenance is missing")
    verify_gate_provenance(provenance)
    fixture = summary.get("fixture")
    if not isinstance(fixture, dict):
        raise AssertionError("competition gate fixture identity is missing")
    primary = fixture.get("primary_origin")
    if not isinstance(primary, str):
        raise AssertionError("competition gate primary origin is missing")
    cases = summary.get("cases")
    if not isinstance(cases, list) or len(cases) != len(CASES):
        raise AssertionError("competition gate case set is incomplete")
    for recorded, (case_name, path, expected_finding) in zip(cases, CASES):
        if not isinstance(recorded, dict) or recorded.get("case") != case_name:
            raise AssertionError("competition gate case order or identity changed")
        job_id = recorded.get("job_id")
        if not isinstance(job_id, str):
            raise AssertionError("competition gate case job identity is missing")
        persisted = _strict_json_file(RECEIPTS_DIR / f"{job_id}.json", 8 * 1024 * 1024)
        observed = _verify_probe_receipt(
            persisted,
            case_request(primary, path),
            expected_finding,
        )
        observed["case"] = case_name
        if observed != recorded:
            raise AssertionError("competition gate case differs from persisted evidence")
        if (
            recorded["rootfs_sha256"] != provenance["browser_rootfs"]["sha256"]
            or recorded["rootfs_receipt_sha256"]
            != provenance["browser_rootfs"]["build_receipt"]["sha256"]
        ):
            raise AssertionError("competition gate case rootfs provenance changed")
    expected_counts = {"post": 0, "websocket": 0, "popup": 0, "unauthorized": 0}
    if summary.get("fixture_counts") != {
        "primary": expected_counts,
        "secondary": expected_counts,
    }:
        raise AssertionError("competition gate fixture counts are not clean")
    current_preflight = preflight_firecracker(profile="browser")
    if not current_preflight.ready:
        raise AssertionError("competition host no longer passes Firecracker preflight")
    if _owned_stale_job_tokens(DEFAULT_RUNTIME_ROOT, DEFAULT_CGROUP_ROOT):
        raise AssertionError("owned Firecracker resources remain after the gate")
    return summary


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin")
    parser.add_argument("--unauthorized-origin")
    parser.add_argument("--control-token-file", type=Path)
    parser.add_argument("--verify-output", action="store_true")
    parser.add_argument(
        "--output",
        type=Path,
        default=RECEIPTS_DIR / "firecracker-e2e-gate.json",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    if args.verify_output:
        result = verify_gate_result(args.output)
        print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True))
        return 0
    if not args.origin or not args.unauthorized_origin or args.control_token_file is None:
        raise SystemExit(
            "--origin, --unauthorized-origin, and --control-token-file are required"
        )
    result = run_gate(
        origin=args.origin,
        unauthorized_origin=args.unauthorized_origin,
        token_file=args.control_token_file,
        output_path=args.output,
    )
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
