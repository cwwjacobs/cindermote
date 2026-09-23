#!/bin/sh
set -eu

gate_fd=${CINDERMOTE_LAUNCH_GATE_FD:-}
if [ -n "$gate_fd" ]; then
  case "$gate_fd" in
    *[!0-9]*) exit 125 ;;
  esac
  launch_token=
  eval "IFS= read -r launch_token <&$gate_fd" || exit 125
  [ "$launch_token" = 'cindermote-cgroup-ready-v1' ] || exit 125
  eval "exec $gate_fd<&-"
  exec unshare --mount --net --ipc --uts --pid --fork --kill-child "$@"
fi

# A privileged launch without the host gate is never allowed to fall through
# to the degraded path.
[ "$(id -u)" -ne 0 ] || exit 125

printf '%s\n' 'WARNING: Cindermote is using degraded-user isolation (no cgroups or mlock).' >&2
exec unshare --user --map-root-user --mount --net --ipc --uts "$@"
