#!/bin/sh
# Uses curl; an existing ~/.netrc may supply credentials when needed.
set -eu
[ "$#" -eq 1 ] || { echo 'Usage: webhook.sh HTTPS_URL' >&2; exit 2; }
case "$1" in https://*) ;; *) echo 'An HTTPS webhook URL is required' >&2; exit 2;; esac
: "${NETSHIFT_EVENT_JSON:?A NetShift event is required}"
exec curl --fail --silent --show-error --connect-timeout 3 --max-time 10 --netrc-optional --header 'Content-Type: application/json' --data-binary "$NETSHIFT_EVENT_JSON" -- "$1"
