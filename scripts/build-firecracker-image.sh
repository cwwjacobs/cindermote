#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CACHE_DIR="${CINDERMOTE_CACHE_DIR:-${PROJECT_DIR}/.cindermote/cache}"
IMAGE_DIR="${CACHE_DIR}/images"
ROOTFS="${IMAGE_DIR}/browser-rootfs.ext4"
RECEIPT="${IMAGE_DIR}/browser-rootfs.receipt.json"
TAG="cindermote-browser-rootfs:v1"
TOOLCHAIN_TAG="cindermote-rootfs-toolchain:v1"
ROOTFS_MIB="${CINDERMOTE_ROOTFS_MIB:-1536}"
SOURCE_DATE_EPOCH=1784160000
FILESYSTEM_UUID="7a1c357e-64a8-4ef8-9cb1-7a2fd676dd10"
DIRECTORY_HASH_SEED="11111111-2222-3333-4444-555555555555"
BASE_IMAGE_DIGEST="sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818"
DEBIAN_SNAPSHOT="20260716T110000Z"
CHROMIUM_PACKAGE_VERSION="150.0.7871.124-1~deb12u1"
E2FSPROGS_VERSION="1.47.0-2+b2"
FAKEROOT_VERSION="1.31-1.2"
PLATFORM_TOOLS_URL="https://dl.google.com/android/repository/platform-tools_r33.0.3-linux.zip"
PLATFORM_TOOLS_SHA256="ab885c20f1a9cb528eb145b9208f53540efa3d26258ac3ce4363570a0846f8f7"
E2FSDROID_SHA256="5acfcba27c1a362a9df97879100910d79014090c1ef999a7bc9d7a74998fa0b4"

docker_no_cache="${CINDERMOTE_DOCKER_NO_CACHE:-0}"
candidate=0
while (( $# )); do
  case "$1" in
    --no-cache) docker_no_cache=1 ;;
    --candidate) candidate=1 ;;
    *) echo "usage: $0 [--no-cache] [--candidate]" >&2; exit 2 ;;
  esac
  shift
done

for command in awk docker id install mktemp python3 sha256sum tr; do
  command -v "$command" >/dev/null || {
    echo "missing required command: $command" >&2
    exit 2
  }
done

case "$ROOTFS_MIB" in
  ''|*[!0-9]*) echo "CINDERMOTE_ROOTFS_MIB must be an integer" >&2; exit 2 ;;
esac
if (( ROOTFS_MIB < 768 || ROOTFS_MIB > 4096 )); then
  echo "CINDERMOTE_ROOTFS_MIB must be in 768..4096" >&2
  exit 2
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/cindermote-rootfs.XXXXXX")"
container=""
cleanup() {
  if [[ -n "$container" ]]; then docker rm --force "$container" >/dev/null 2>&1 || true; fi
  rm -rf -- "$work"
}
trap cleanup EXIT

docker_build_args=(--pull=false --network=default --provenance=false)
if [[ "$docker_no_cache" == "1" ]]; then
  docker_build_args+=(--no-cache)
elif [[ "$docker_no_cache" != "0" ]]; then
  echo "CINDERMOTE_DOCKER_NO_CACHE must be 0 or 1" >&2
  exit 2
fi

docker build "${docker_build_args[@]}" \
  --build-arg "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}" \
  --build-arg "DEBIAN_SNAPSHOT=${DEBIAN_SNAPSHOT}" \
  --build-arg "CHROMIUM_VERSION=${CHROMIUM_PACKAGE_VERSION}" \
  --file "${PROJECT_DIR}/images/firecracker/Containerfile" \
  --tag "$TAG" "$PROJECT_DIR"
docker build "${docker_build_args[@]}" \
  --build-arg "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}" \
  --build-arg "DEBIAN_SNAPSHOT=${DEBIAN_SNAPSHOT}" \
  --build-arg "E2FSPROGS_VERSION=${E2FSPROGS_VERSION}" \
  --build-arg "FAKEROOT_VERSION=${FAKEROOT_VERSION}" \
  --build-arg "PLATFORM_TOOLS_URL=${PLATFORM_TOOLS_URL}" \
  --build-arg "PLATFORM_TOOLS_SHA256=${PLATFORM_TOOLS_SHA256}" \
  --build-arg "E2FSDROID_SHA256=${E2FSDROID_SHA256}" \
  --file "${PROJECT_DIR}/images/firecracker/RootfsToolchain.Containerfile" \
  --tag "$TOOLCHAIN_TAG" "$PROJECT_DIR"
container="$(docker create "$TAG")"
mkdir -p "$IMAGE_DIR"
docker export "$container" --output "${work}/rootfs.tar"

# Every filesystem-writing tool runs in the pinned, offline toolchain image.
# The host supplies Docker and a bind-mounted scratch directory only.
docker run --rm \
  --network=none \
  --read-only \
  --cap-drop=ALL \
  --security-opt no-new-privileges \
  --pids-limit 128 \
  --memory 3g \
  --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m \
  --mount "type=bind,source=${work},target=/work" \
  --env "ROOTFS_MIB=${ROOTFS_MIB}" \
  --env "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}" \
  --env "FILESYSTEM_UUID=${FILESYSTEM_UUID}" \
  --env "DIRECTORY_HASH_SEED=${DIRECTORY_HASH_SEED}" \
  "$TOOLCHAIN_TAG"

browser_version="$(docker run --rm --entrypoint /bin/cat "$TAG" /opt/cindermote/chromium.version | tr -d '\r\n')"
cryptography_version="$(docker run --rm --entrypoint /usr/bin/dpkg-query "$TAG" -W -f='${Version}' python3-cryptography)"
libsodium_version="$(docker run --rm --entrypoint /usr/bin/dpkg-query "$TAG" -W -f='${Version}' libsodium23)"
browser_sha="$(sha256sum "${work}/chromium.rootfs" | awk '{print $1}')"
container_browser_sha="$(docker run --rm --entrypoint /bin/cat "$TAG" /opt/cindermote/chromium.sha256 | awk '{print $1}')"
if [[ "$browser_sha" != "$container_browser_sha" ]]; then
  echo "rootfs Chromium digest differs from the verified container" >&2
  exit 2
fi
agent_sha="$(sha256sum "${work}/browser_agent.rootfs.py" | awk '{print $1}')"
agent_probe_agent_sha="$(sha256sum "${work}/agent_probe_agent.rootfs.py" | awk '{print $1}')"
agent_probe_init_sha="$(sha256sum "${work}/agent_probe_init.rootfs.py" | awk '{print $1}')"
agent_probe_canonical_sha="$(sha256sum "${work}/agent_probe_canonical.rootfs.py" | awk '{print $1}')"
agent_probe_evidence_sha="$(sha256sum "${work}/agent_probe_evidence.rootfs.py" | awk '{print $1}')"
agent_probe_hpke_sha="$(sha256sum "${work}/agent_probe_hpke.rootfs.py" | awk '{print $1}')"
agent_probe_protocol_sha="$(sha256sum "${work}/agent_probe_protocol.rootfs.py" | awk '{print $1}')"
agent_probe_secretstream_sha="$(sha256sum "${work}/agent_probe_secretstream.rootfs.py" | awk '{print $1}')"
contract_sha="$(sha256sum "${work}/browser_contract.rootfs.py" | awk '{print $1}')"
init_sha="$(sha256sum "${work}/cindermote-init.rootfs" | awk '{print $1}')"
browser_containerfile_sha="$(sha256sum "${PROJECT_DIR}/images/firecracker/Containerfile" | awk '{print $1}')"
toolchain_containerfile_sha="$(sha256sum "${PROJECT_DIR}/images/firecracker/RootfsToolchain.Containerfile" | awk '{print $1}')"
toolchain_script_sha="$(sha256sum "${PROJECT_DIR}/scripts/build-rootfs-in-toolchain.sh" | awk '{print $1}')"
builder_script_sha="$(sha256sum "${PROJECT_DIR}/scripts/build-firecracker-image.sh" | awk '{print $1}')"
[[ "$agent_sha" == "$(sha256sum "${PROJECT_DIR}/guest/browser_agent.py" | awk '{print $1}')" ]] || {
  echo "rootfs browser agent differs from the checked-out source" >&2; exit 2;
}
declare -A agent_probe_sources=(
  [agent_probe_agent_sha]="guest/agent_probe_agent.py"
  [agent_probe_init_sha]="agent_probe/__init__.py"
  [agent_probe_canonical_sha]="agent_probe/canonical.py"
  [agent_probe_evidence_sha]="agent_probe/evidence.py"
  [agent_probe_hpke_sha]="agent_probe/hpke.py"
  [agent_probe_protocol_sha]="agent_probe/protocol.py"
  [agent_probe_secretstream_sha]="agent_probe/secretstream.py"
)
for variable in "${!agent_probe_sources[@]}"; do
  source_path="${agent_probe_sources[$variable]}"
  observed="${!variable}"
  expected="$(sha256sum "${PROJECT_DIR}/${source_path}" | awk '{print $1}')"
  [[ "$observed" == "$expected" ]] || { echo "rootfs ${source_path} differs from checked-out source" >&2; exit 2; }
done
[[ "$contract_sha" == "$(sha256sum "${PROJECT_DIR}/mote/browser_contract.py" | awk '{print $1}')" ]] || {
  echo "rootfs browser contract differs from the checked-out source" >&2; exit 2;
}
[[ "$init_sha" == "$(sha256sum "${PROJECT_DIR}/guest/cindermote-init" | awk '{print $1}')" ]] || {
  echo "rootfs init differs from the checked-out source" >&2; exit 2;
}
install -m 0444 "${work}/browser-rootfs.ext4" "$ROOTFS"
rootfs_sha="$(sha256sum "$ROOTFS" | awk '{print $1}')"

python3 - \
  "$RECEIPT" \
  "$rootfs_sha" \
  "$browser_version" \
  "$browser_sha" \
  "$cryptography_version" \
  "$libsodium_version" \
  "$ROOTFS_MIB" \
  "$agent_sha" \
  "$agent_probe_agent_sha" \
  "$agent_probe_init_sha" \
  "$agent_probe_canonical_sha" \
  "$agent_probe_evidence_sha" \
  "$agent_probe_hpke_sha" \
  "$agent_probe_protocol_sha" \
  "$agent_probe_secretstream_sha" \
  "$contract_sha" \
  "$init_sha" \
  "$browser_containerfile_sha" \
  "$toolchain_containerfile_sha" \
  "$toolchain_script_sha" \
  "$builder_script_sha" \
  "$SOURCE_DATE_EPOCH" \
  "$FILESYSTEM_UUID" \
  "$DIRECTORY_HASH_SEED" \
  "$BASE_IMAGE_DIGEST" \
  "$DEBIAN_SNAPSHOT" \
  "$CHROMIUM_PACKAGE_VERSION" \
  "$E2FSPROGS_VERSION" \
  "$FAKEROOT_VERSION" \
  "$PLATFORM_TOOLS_URL" \
  "$PLATFORM_TOOLS_SHA256" \
  "$E2FSDROID_SHA256" <<'PY'
import json
import os
import sys

(
    path,
    rootfs_sha,
    browser_version,
    browser_sha,
    cryptography_version,
    libsodium_version,
    size_mib,
    agent_sha,
    agent_probe_agent_sha,
    agent_probe_init_sha,
    agent_probe_canonical_sha,
    agent_probe_evidence_sha,
    agent_probe_hpke_sha,
    agent_probe_protocol_sha,
    agent_probe_secretstream_sha,
    contract_sha,
    init_sha,
    browser_containerfile_sha,
    toolchain_containerfile_sha,
    toolchain_script_sha,
    builder_script_sha,
    source_date_epoch,
    filesystem_uuid,
    directory_hash_seed,
    base_image_digest,
    debian_snapshot,
    chromium_package_version,
    e2fsprogs_version,
    fakeroot_version,
    platform_tools_url,
    platform_tools_sha256,
    e2fsdroid_sha256,
) = sys.argv[1:]
receipt = {
    "schema_version": "cindermote.browser-rootfs/v1",
    "source_date_epoch": int(source_date_epoch),
    "filesystem_uuid": filesystem_uuid,
    "directory_hash_seed": directory_hash_seed,
    "rootfs": {"sha256": rootfs_sha, "size_mib": int(size_mib), "read_only_runtime": True},
    "browser": {
        "version": browser_version,
        "binary_sha256": browser_sha,
        "sandbox_required": True,
        "sandbox_uid": 0,
        "sandbox_gid": 0,
        "sandbox_mode": "04755",
    },
    "runtime_packages": {
        "python3-cryptography": cryptography_version,
        "libsodium23": libsodium_version,
    },
    "build_inputs": {
        "base_image_digest": base_image_digest,
        "debian_snapshot": debian_snapshot,
        "chromium_package_version": chromium_package_version,
        "e2fsprogs_package_version": e2fsprogs_version,
        "fakeroot_package_version": fakeroot_version,
        "platform_tools_url": platform_tools_url,
        "platform_tools_sha256": platform_tools_sha256,
        "e2fsdroid_sha256": e2fsdroid_sha256,
    },
    "guest_writes": "tmpfs_only",
    "sources": {
        "guest/browser_agent.py": agent_sha,
        "guest/agent_probe_agent.py": agent_probe_agent_sha,
        "agent_probe/__init__.py": agent_probe_init_sha,
        "agent_probe/canonical.py": agent_probe_canonical_sha,
        "agent_probe/evidence.py": agent_probe_evidence_sha,
        "agent_probe/hpke.py": agent_probe_hpke_sha,
        "agent_probe/protocol.py": agent_probe_protocol_sha,
        "agent_probe/secretstream.py": agent_probe_secretstream_sha,
        "mote/browser_contract.py": contract_sha,
        "guest/cindermote-init": init_sha,
        "images/firecracker/Containerfile": browser_containerfile_sha,
        "images/firecracker/RootfsToolchain.Containerfile": toolchain_containerfile_sha,
        "scripts/build-rootfs-in-toolchain.sh": toolchain_script_sha,
        "scripts/build-firecracker-image.sh": builder_script_sha,
    },
}
temporary = path + ".tmp"
with open(temporary, "w", encoding="utf-8") as handle:
    json.dump(receipt, handle, indent=2, sort_keys=True)
    handle.write("\n")
os.chmod(temporary, 0o444)
os.replace(temporary, path)
PY

printf 'Built verified browser rootfs: %s\n' "$ROOTFS"
printf 'Receipt: %s\n' "$RECEIPT"
printf 'Lock rootfs sha256: %s\n' "$rootfs_sha"
receipt_sha="$(sha256sum "$RECEIPT" | awk '{print $1}')"
printf 'Lock receipt sha256: %s\n' "$receipt_sha"

if (( candidate )); then
  printf 'Candidate mode: review and deliberately repin both hashes before runtime admission.\n'
else
  python3 - "${PROJECT_DIR}/policy/firecracker-assets.lock.json" "$rootfs_sha" "$receipt_sha" <<'PY'
import json
import sys

lock_path, rootfs_sha, receipt_sha = sys.argv[1:]
with open(lock_path, encoding="utf-8") as handle:
    locked = json.load(handle)["browser_rootfs"]
if locked.get("sha256") != rootfs_sha:
    raise SystemExit("built rootfs differs from the checked-in release lock; use --candidate only for an intentional new release")
if locked.get("build_receipt_sha256") != receipt_sha:
    raise SystemExit("built rootfs receipt differs from the checked-in release lock; use --candidate only for an intentional new release")
print("Release lock matched exactly.")
PY
fi
