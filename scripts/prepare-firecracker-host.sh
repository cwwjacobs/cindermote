#!/usr/bin/env bash
set -euo pipefail

export PATH=/usr/sbin:/usr/bin:/sbin:/bin

RUNTIME_ROOT="${CINDERMOTE_RUNTIME_ROOT:-/run/cindermote}"
RUNTIME_SIZE="${CINDERMOTE_RUNTIME_SIZE:-8G}"
JAILER_SIZE="${CINDERMOTE_JAILER_SIZE:-6G}"
CGROUP_ROOT="${CINDERMOTE_CGROUP_ROOT:-/sys/fs/cgroup/cindermote}"
VMM_USER="cindermote-vmm"
VMM_GROUP="cindermote-vmm"
PROXY_USER="cindermote-proxy"
PROXY_GROUP="cindermote-proxy"

if (( EUID != 0 )); then
  echo "prepare-firecracker-host.sh must run as root" >&2
  exit 2
fi
for command in findmnt getent groupadd id install mount mountpoint passwd stat useradd; do
  command -v "$command" >/dev/null || { echo "missing command: $command" >&2; exit 2; }
done
[[ -r /dev/kvm && -w /dev/kvm ]] || { echo "/dev/kvm is not readable and writable" >&2; exit 1; }
[[ -e /dev/net/tun ]] || { echo "/dev/net/tun is unavailable" >&2; exit 1; }
if [[ "$(tail -n +2 /proc/swaps | wc -l)" -ne 0 ]]; then
  echo "host swap is active; disable swap before creating a RAM-confidential runtime" >&2
  exit 1
fi
if [[ "$(stat -f -c %T /sys/fs/cgroup)" != "cgroup2fs" ]]; then
  echo "cgroup v2 is required" >&2
  exit 1
fi

SERVICE_SHELL="$(command -v nologin || command -v false)"
RESOLVED_UID=""
RESOLVED_GID=""

provision_service_identity() {
  local account="$1"
  local account_group="$2"
  local label="$3"
  local passwd_entry group_entry shadow_entry
  local account_name account_uid account_gid account_home account_shell
  local group_name group_gid group_members shadow_name shadow_password
  local -a account_groups

  if ! getent group "$account_group" >/dev/null; then
    groupadd --system "$account_group"
  fi
  if ! getent passwd "$account" >/dev/null; then
    useradd \
      --system \
      --gid "$account_group" \
      --home-dir /nonexistent \
      --no-create-home \
      --shell "$SERVICE_SHELL" \
      "$account"
  fi
  # An existing service account is brought to the same fail-closed state as a
  # newly provisioned one; a non-login shell alone is not a password lock.
  passwd --lock "$account" >/dev/null

  passwd_entry="$(getent passwd "$account")"
  group_entry="$(getent group "$account_group")"
  shadow_entry="$(getent shadow "$account")"
  IFS=: read -r account_name _ account_uid account_gid _ account_home account_shell <<<"$passwd_entry"
  IFS=: read -r group_name _ group_gid group_members <<<"$group_entry"
  IFS=: read -r shadow_name shadow_password _ <<<"$shadow_entry"
  if [[ "$account_name" != "$account" || "$group_name" != "$account_group" || "$shadow_name" != "$account" ]]; then
    echo "dedicated $label identity did not resolve exactly" >&2
    exit 1
  fi
  if [[ ! "$account_uid" =~ ^[0-9]+$ || ! "$account_gid" =~ ^[0-9]+$ || ! "$group_gid" =~ ^[0-9]+$ ]]; then
    echo "dedicated $label identity has malformed numeric identifiers" >&2
    exit 1
  fi
  if [[ "$account_uid" -eq 0 || "$account_uid" -eq 65533 || "$account_uid" -eq 65534 || "$group_gid" -eq 0 || "$group_gid" -eq 65533 || "$group_gid" -eq 65534 ]]; then
    echo "dedicated $label identity resolved to an unsafe generic identity" >&2
    exit 1
  fi
  if [[ "$account_gid" != "$group_gid" || "$account_home" != "/nonexistent" ]]; then
    echo "dedicated $label identity has an unexpected primary group or home" >&2
    exit 1
  fi
  case "${account_shell##*/}" in
    nologin|false) ;;
    *) echo "dedicated $label identity must have a non-login shell" >&2; exit 1 ;;
  esac
  case "$shadow_password" in
    \!*|\**) ;;
    *) echo "dedicated $label identity must have a locked password" >&2; exit 1 ;;
  esac
  if [[ -n "$group_members" && "$group_members" != "$account" ]]; then
    echo "dedicated $label group has unexpected explicit members" >&2
    exit 1
  fi
  read -r -a account_groups <<<"$(id -G "$account")"
  if [[ "${#account_groups[@]}" -ne 1 || "${account_groups[0]}" != "$group_gid" ]]; then
    echo "dedicated $label identity must not have supplementary groups" >&2
    exit 1
  fi
  while IFS=: read -r owner _; do
    if [[ -n "$owner" && "$owner" != "$account" ]]; then
      echo "dedicated $label uid is shared by another account" >&2
      exit 1
    fi
  done < <(getent passwd "$account_uid")
  while IFS=: read -r owner _; do
    if [[ -n "$owner" && "$owner" != "$account_group" ]]; then
      echo "dedicated $label gid is shared by another group" >&2
      exit 1
    fi
  done < <(getent group "$group_gid")

  RESOLVED_UID="$account_uid"
  RESOLVED_GID="$group_gid"
}

provision_service_identity "$VMM_USER" "$VMM_GROUP" "VMM"
VMM_UID="$RESOLVED_UID"
VMM_GID="$RESOLVED_GID"
provision_service_identity "$PROXY_USER" "$PROXY_GROUP" "proxy"
PROXY_UID="$RESOLVED_UID"
PROXY_GID="$RESOLVED_GID"

if [[ "$PROXY_UID" == "$VMM_UID" || "$PROXY_UID" == "$VMM_GID" || "$PROXY_GID" == "$VMM_UID" || "$PROXY_GID" == "$VMM_GID" ]]; then
  echo "dedicated proxy and VMM identities must have disjoint numeric identifiers" >&2
  exit 1
fi

install -d -o root -g root -m 0700 "$RUNTIME_ROOT"
if mountpoint -q "$RUNTIME_ROOT"; then
  [[ "$(stat -f -c %T "$RUNTIME_ROOT")" == "tmpfs" ]] || {
    echo "$RUNTIME_ROOT is already a non-tmpfs mount" >&2
    exit 1
  }
else
  mount -t tmpfs -o "size=${RUNTIME_SIZE},mode=0700,nosuid,nodev,noswap" \
    cindermote-runtime "$RUNTIME_ROOT"
fi

install -d -o root -g root -m 0700 \
  "$RUNTIME_ROOT/assets" "$RUNTIME_ROOT/jailer" "$RUNTIME_ROOT/locks"

# Jailer creates /dev/kvm and /dev/net/tun inside each chroot. Keep that
# device-capable surface on a dedicated root-only RAM mount; the surrounding
# runtime remains nodev.
if mountpoint -q "$RUNTIME_ROOT/jailer"; then
  [[ "$(stat -f -c %T "$RUNTIME_ROOT/jailer")" == "tmpfs" ]] || {
    echo "$RUNTIME_ROOT/jailer is already a non-tmpfs mount" >&2
    exit 1
  }
else
  mount -t tmpfs -o "size=${JAILER_SIZE},mode=0700,dev,nosuid,noswap" \
    cindermote-jailer "$RUNTIME_ROOT/jailer"
fi

install -d -o root -g root -m 0755 "$CGROUP_ROOT"
install -d -o root -g root -m 0755 "$CGROUP_ROOT/firecracker"
for controller in cpu memory pids; do
  if grep -qw "$controller" "$(dirname "$CGROUP_ROOT")/cgroup.controllers"; then
    printf '+%s\n' "$controller" > "$(dirname "$CGROUP_ROOT")/cgroup.subtree_control"
  else
    echo "required cgroup controller unavailable: $controller" >&2
    exit 1
  fi
  printf '+%s\n' "$controller" > "$CGROUP_ROOT/cgroup.subtree_control"
  printf '+%s\n' "$controller" > "$CGROUP_ROOT/firecracker/cgroup.subtree_control"
done

options="$(findmnt -n -o OPTIONS --target "$RUNTIME_ROOT")"
for required in rw nosuid nodev noswap; do
  case ",$options," in
    *",$required,"*) ;;
    *) echo "$RUNTIME_ROOT is missing mount option: $required" >&2; exit 1 ;;
  esac
done

jailer_options="$(findmnt -n -o OPTIONS --target "$RUNTIME_ROOT/jailer")"
for required in rw nosuid noswap; do
  case ",$jailer_options," in
    *",$required,"*) ;;
    *) echo "$RUNTIME_ROOT/jailer is missing mount option: $required" >&2; exit 1 ;;
  esac
done
case ",$jailer_options," in
  *,nodev,*) echo "$RUNTIME_ROOT/jailer must permit jailer-created device nodes" >&2; exit 1 ;;
esac

printf 'Firecracker host runtime ready at %s (tmpfs, swap disabled).\n' "$RUNTIME_ROOT"
