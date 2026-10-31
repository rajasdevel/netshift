#!/bin/sh
# Uses the existing AWS CLI identity. Args: hosted-zone-id record.example.com
set -eu
[ "$#" -eq 2 ] || { echo 'Usage: route53-ddns.sh HOSTED_ZONE RECORD_NAME' >&2; exit 2; }
case "$1" in ''|*[!A-Za-z0-9]*) echo 'Invalid hosted zone ID' >&2; exit 2;; esac
case "$2" in ''|*[!A-Za-z0-9.-]*) echo 'Invalid DNS record name' >&2; exit 2;; esac
case "${NETSHIFT_IP:-}" in ''|*[!0-9.]*) echo 'A confirmed IPv4 is required' >&2; exit 2;; esac
change=$(printf '{"Changes":[{"Action":"UPSERT","ResourceRecordSet":{"Name":"%s","Type":"A","TTL":60,"ResourceRecords":[{"Value":"%s"}]}}]}' "$2" "$NETSHIFT_IP")
exec aws route53 change-resource-record-sets --hosted-zone-id "$1" --change-batch "$change" --cli-connect-timeout 3 --cli-read-timeout 10 --no-cli-pager
