#!/usr/bin/env bash
set -euo pipefail

readonly WORK_DIR=/work
readonly ROOTFS_MIB="${ROOTFS_MIB:?ROOTFS_MIB is required}"
readonly SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH is required}"
readonly FILESYSTEM_UUID="${FILESYSTEM_UUID:?FILESYSTEM_UUID is required}"
readonly DIRECTORY_HASH_SEED="${DIRECTORY_HASH_SEED:?DIRECTORY_HASH_SEED is required}"
readonly ROOTFS="${WORK_DIR}/browser-rootfs.ext4"
readonly SOURCE_TREE="${WORK_DIR}/rootfs"
readonly FAKEROOT_STATE="${WORK_DIR}/fakeroot.state"

test -f "${WORK_DIR}/rootfs.tar"
test ! -e "$ROOTFS"
test ! -e "$SOURCE_TREE"
mkdir -m 0700 "$SOURCE_TREE"

fakeroot -s "$FAKEROOT_STATE" -- \
  tar --extract --numeric-owner --file "${WORK_DIR}/rootfs.tar" --directory "$SOURCE_TREE"

truncate -s "${ROOTFS_MIB}M" "$ROOTFS"
export E2FSPROGS_FAKE_TIME="$SOURCE_DATE_EPOCH"
mkfs.ext4 -q -F \
  -L cindermote-root \
  -U "$FILESYSTEM_UUID" \
  -O '^orphan_file' \
  -E lazy_itable_init=0,lazy_journal_init=0 \
  "$ROOTFS"
fakeroot -i "$FAKEROOT_STATE" -- e2fsdroid \
  -e \
  -T "$SOURCE_DATE_EPOCH" \
  -f "$SOURCE_TREE" \
  "$ROOTFS"

# This e2fsdroid build does not preserve host executable bits: without an
# fs_config (which requires an entry for every file) it writes 0644 for
# every regular file, leaving the guest's init, shell, interpreter, and
# helpers non-executable (kernel init fails with EACCES).  Restore the
# executable bit inode-by-inode for every file that carries one in the
# extracted tree, the same attestation style as chrome-sandbox below.
find "$SOURCE_TREE" -type f -perm /111 -printf '%P\n' | sort \
  | while IFS= read -r relative; do
      printf 'set_inode_field /%s mode 0100755\n' "$relative"
    done >"${WORK_DIR}/exec-fixups.debugfs"
debugfs -w -f "${WORK_DIR}/exec-fixups.debugfs" "$ROOTFS" >/dev/null 2>&1
printf '%s\n' \
  /usr/sbin/cindermote-init \
  /usr/bin/dash \
  /usr/bin/python3.11 \
  /usr/bin/mount \
  /usr/bin/mkdir \
  /usr/bin/ip \
  >"${WORK_DIR}/required-executables"
while IFS= read -r executable; do
  debugfs -R "stat ${executable}" "$ROOTFS" >"${WORK_DIR}/executable.stat" 2>/dev/null
  grep -Eq '\bType:[[:space:]]+regular[[:space:]]+Mode:[[:space:]]+0755\b' \
    "${WORK_DIR}/executable.stat" || {
      echo "required guest executable lost its exec bit: ${executable}" >&2
      exit 2
    }
done <"${WORK_DIR}/required-executables"
printf '%s\n' \
  "set_super_value hash_seed ${DIRECTORY_HASH_SEED}" \
  'close -a' \
  | debugfs -w "$ROOTFS" >/dev/null 2>&1

# Chromium refuses a helper that is not root-owned setuid. Attest the inode in
# the filesystem bytes rather than trusting the extracted source tree.
debugfs -w -R "set_inode_field /usr/lib/chromium/chrome-sandbox uid 0" "$ROOTFS" >/dev/null
debugfs -w -R "set_inode_field /usr/lib/chromium/chrome-sandbox gid 0" "$ROOTFS" >/dev/null
debugfs -w -R "set_inode_field /usr/lib/chromium/chrome-sandbox mode 0104755" "$ROOTFS" >/dev/null
debugfs -R "stat /usr/lib/chromium/chrome-sandbox" "$ROOTFS" \
  >"${WORK_DIR}/chrome-sandbox.stat" 2>/dev/null
grep -Eq '\bType:[[:space:]]+regular[[:space:]]+Mode:[[:space:]]+04755\b' \
  "${WORK_DIR}/chrome-sandbox.stat"
grep -Eq '\bUser:[[:space:]]+0[[:space:]]+Group:[[:space:]]+0\b' \
  "${WORK_DIR}/chrome-sandbox.stat"

e2fsck -fn "$ROOTFS" >/dev/null
debugfs -R "dump /usr/lib/chromium/chromium ${WORK_DIR}/chromium.rootfs" "$ROOTFS" >/dev/null
debugfs -R "dump /opt/cindermote/browser_agent.py ${WORK_DIR}/browser_agent.rootfs.py" "$ROOTFS" >/dev/null
debugfs -R "dump /opt/cindermote/agent_probe_agent.py ${WORK_DIR}/agent_probe_agent.rootfs.py" "$ROOTFS" >/dev/null
debugfs -R "dump /opt/cindermote/agent_probe/__init__.py ${WORK_DIR}/agent_probe_init.rootfs.py" "$ROOTFS" >/dev/null
debugfs -R "dump /opt/cindermote/agent_probe/canonical.py ${WORK_DIR}/agent_probe_canonical.rootfs.py" "$ROOTFS" >/dev/null
debugfs -R "dump /opt/cindermote/agent_probe/evidence.py ${WORK_DIR}/agent_probe_evidence.rootfs.py" "$ROOTFS" >/dev/null
debugfs -R "dump /opt/cindermote/agent_probe/hpke.py ${WORK_DIR}/agent_probe_hpke.rootfs.py" "$ROOTFS" >/dev/null
debugfs -R "dump /opt/cindermote/agent_probe/protocol.py ${WORK_DIR}/agent_probe_protocol.rootfs.py" "$ROOTFS" >/dev/null
debugfs -R "dump /opt/cindermote/agent_probe/secretstream.py ${WORK_DIR}/agent_probe_secretstream.rootfs.py" "$ROOTFS" >/dev/null
debugfs -R "dump /opt/cindermote/browser_contract.py ${WORK_DIR}/browser_contract.rootfs.py" "$ROOTFS" >/dev/null
debugfs -R "dump /sbin/cindermote-init ${WORK_DIR}/cindermote-init.rootfs" "$ROOTFS" >/dev/null
