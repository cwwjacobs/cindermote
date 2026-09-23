#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_DIR="${PROJECT_DIR}/dist"

mkdir -p "${OUTPUT_DIR}"

PACKAGE_NAME="Cindermote_v1_clean"
TMP_STAGE="$(mktemp -d /tmp/cindermote_pkg.XXXXXX)"
STAGE_DIR="${TMP_STAGE}/${PACKAGE_NAME}"

echo "=== Packaging clean Cindermote release ==="

# Copy project files into temporary staging area
rsync -a \
  --exclude='.git' \
  --exclude='.observer_key' \
  --exclude='.tainted_hosts' \
  --exclude='.decommissioned_hosts' \
  --exclude='alerts' \
  --exclude='quarantine' \
  --exclude='receipts' \
  --exclude='mf-run-*' \
  --exclude='cf-run-*' \
  --exclude='__pycache__' \
  --exclude='.pytest_cache' \
  --exclude='*.pyc' \
  --exclude='.cindermote/cache' \
  --exclude='.cindermote/runtime' \
  --exclude='.cindermote/replays' \
  --exclude='scratch' \
  --exclude='dist' \
  "${PROJECT_DIR}/" "${STAGE_DIR}/"

# Normalize permissions
find "${STAGE_DIR}" -type d -exec chmod 755 {} +
find "${STAGE_DIR}" -type f -exec chmod 644 {} +
find "${STAGE_DIR}/scripts" -type f -name "*.sh" -exec chmod 755 {} +
find "${STAGE_DIR}/scripts" -type f -name "*.py" -exec chmod 755 {} +
find "${STAGE_DIR}/tests/fixtures" -type f -name "*.py" -exec chmod 755 {} +

TAR_PATH="${OUTPUT_DIR}/${PACKAGE_NAME}.tar.gz"
ZIP_PATH="${OUTPUT_DIR}/${PACKAGE_NAME}.zip"

(cd "${TMP_STAGE}" && tar -czf "${TAR_PATH}" "${PACKAGE_NAME}")
(cd "${TMP_STAGE}" && zip -q -r "${ZIP_PATH}" "${PACKAGE_NAME}")

rm -rf "${TMP_STAGE}"

# Compute SHA-256 checksums
SHA_FILE="${OUTPUT_DIR}/SHA256SUMS.txt"
(cd "${OUTPUT_DIR}" && sha256sum "${PACKAGE_NAME}.tar.gz" "${PACKAGE_NAME}.zip" > "${SHA_FILE}")

echo "Packaged clean release artifacts:"
echo "  - Tarball:  ${TAR_PATH}"
echo "  - Zip:      ${ZIP_PATH}"
echo "  - Checksum: ${SHA_FILE}"
