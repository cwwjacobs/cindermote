#!/usr/bin/env bash
set -euo pipefail

readonly VERSION="1.17.0"
readonly ARCH="x86_64"
readonly ARCHIVE_SHA256="06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558"
readonly FIRECRACKER_SHA256="99ad0f5cd0514a88aad0e9ae8cfdb3cc3b4ab9d190e1194602406c786b5de7a5"
readonly JAILER_SHA256="65ef226e96f0ceda55ba643f445801ef2cc0ea667ef67cad8ac4f406c9c8434f"
readonly KERNEL_VERSION="6.1.188"
readonly KERNEL_SHA256="c16288854c798ded46c45b3ccab4bc85b8041552ab50f899fecbad550a641e92"
readonly RELEASE_URL="https://github.com/firecracker-microvm/firecracker/releases/download/v${VERSION}/firecracker-v${VERSION}-${ARCH}.tgz"
readonly KERNEL_URL="https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20261016-5732b8331e1e-0/${ARCH}/vmlinux-${KERNEL_VERSION}"

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CACHE_DIR="${CINDERMOTE_CACHE_DIR:-${PROJECT_DIR}/.cindermote/cache}"
INSTALL_DIR="${CACHE_DIR}/firecracker/v${VERSION}/${ARCH}"
KERNEL_DIR="${CACHE_DIR}/kernels"

case "$(uname -m)" in
  x86_64) ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 2 ;;
esac

for command in curl sha256sum tar install mktemp; do
  command -v "$command" >/dev/null || {
    echo "missing required command: $command" >&2
    exit 2
  }
done

work="$(mktemp -d "${TMPDIR:-/tmp}/cindermote-firecracker.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT

archive="${work}/firecracker.tgz"
kernel="${work}/vmlinux-${KERNEL_VERSION}"
curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
  --retry 3 --connect-timeout 10 --max-time 300 \
  --output "$archive" "$RELEASE_URL"
printf '%s  %s\n' "$ARCHIVE_SHA256" "$archive" | sha256sum --check --strict

tar --extract --gzip --file "$archive" --directory "$work" \
  "release-v${VERSION}-${ARCH}/firecracker-v${VERSION}-${ARCH}" \
  "release-v${VERSION}-${ARCH}/jailer-v${VERSION}-${ARCH}" \
  "release-v${VERSION}-${ARCH}/LICENSE" \
  "release-v${VERSION}-${ARCH}/NOTICE"

release="${work}/release-v${VERSION}-${ARCH}"
printf '%s  %s\n' "$FIRECRACKER_SHA256" "${release}/firecracker-v${VERSION}-${ARCH}" | sha256sum --check --strict
printf '%s  %s\n' "$JAILER_SHA256" "${release}/jailer-v${VERSION}-${ARCH}" | sha256sum --check --strict

curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
  --retry 3 --connect-timeout 10 --max-time 300 \
  --output "$kernel" "$KERNEL_URL"
printf '%s  %s\n' "$KERNEL_SHA256" "$kernel" | sha256sum --check --strict

install -d -m 0755 "$INSTALL_DIR" "$KERNEL_DIR" "${CACHE_DIR}/firecracker/v${VERSION}"
install -m 0755 "${release}/firecracker-v${VERSION}-${ARCH}" "${INSTALL_DIR}/firecracker"
install -m 0755 "${release}/jailer-v${VERSION}-${ARCH}" "${INSTALL_DIR}/jailer"
install -m 0644 "${release}/LICENSE" "${CACHE_DIR}/firecracker/v${VERSION}/LICENSE"
install -m 0644 "${release}/NOTICE" "${CACHE_DIR}/firecracker/v${VERSION}/NOTICE"
install -m 0444 "$kernel" "${KERNEL_DIR}/vmlinux-${KERNEL_VERSION}"

printf 'Firecracker v%s, jailer, and Linux %s verified and installed under %s\n' \
  "$VERSION" "$KERNEL_VERSION" "$CACHE_DIR"
