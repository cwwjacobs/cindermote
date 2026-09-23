#!/usr/bin/env bash
set -euo pipefail

readonly VERSION="1.16.1"
readonly ARCH="x86_64"
readonly ARCHIVE_SHA256="382a02a869e4d6d5cb14c40577f9545e8458021ea8b0b2d3fc10ec14d9c242e6"
readonly FIRECRACKER_SHA256="2fd0171309af7e24cf8dafc8a6f921c1434c49b5f9349bb996b7ed0a4deb8aa7"
readonly JAILER_SHA256="1f3a0c1fe86212d0001819bfe0819071c01208b3ccc9398c3b3bc1b84cf21edd"
readonly KERNEL_VERSION="6.1.155"
readonly KERNEL_SHA256="e20e46d0c36c55c0d1014eb20576171b3f3d922260d9f792017aeff53af3d4f2"
readonly RELEASE_URL="https://github.com/firecracker-microvm/firecracker/releases/download/v${VERSION}/firecracker-v${VERSION}-${ARCH}.tgz"
readonly KERNEL_URL="https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.15/${ARCH}/vmlinux-${KERNEL_VERSION}"

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
