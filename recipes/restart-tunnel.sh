#!/bin/sh
# Restart an existing user-managed tunnel service. Never creates a tunnel.
set -eu
[ "$#" -eq 1 ] || { echo 'Usage: restart-tunnel.sh SERVICE_LABEL' >&2; exit 2; }
case "$1" in ''|-*|*[!A-Za-z0-9._-]*) echo 'Invalid service label' >&2; exit 2;; esac
case "$(uname -s)" in
  Darwin) exec launchctl kickstart -k "gui/$(id -u)/$1" ;;
  Linux) exec systemctl --user restart -- "$1" ;;
  *) echo 'macOS or Linux required' >&2; exit 2 ;;
esac
