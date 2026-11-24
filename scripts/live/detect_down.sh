#!/usr/bin/env bash
# Tear down the detection stack: stop the receiver + tunnel. With --delete-webhook
# (and SPCI_TARGET_REPO set) also remove the repo webhook. The persisted secret in
# $SPCI_DETECT_STATE is kept so detect_up.sh reuses it next time.
# Usage:  scripts/live/detect_down.sh [--delete-webhook]
set -uo pipefail
pkill -f 'webhook_receiver[.]py' 2>/dev/null && echo "receiver stopped" || echo "receiver not running"
pkill -f 'cloudflared tunnel' 2>/dev/null && echo "tunnel stopped" || echo "tunnel not running"
if [ "${1:-}" = "--delete-webhook" ] && [ -n "${SPCI_TARGET_REPO:-}" ]; then
  A() { GH_TOKEN="${SPCI_GH_ADMIN_TOKEN:-$(cat ~/ir-admin)}" gh api "$@"; }
  A "/repos/$SPCI_TARGET_REPO/hooks" --jq '.[].id' 2>/dev/null \
    | while read -r h; do A -X DELETE "/repos/$SPCI_TARGET_REPO/hooks/$h" >/dev/null && echo "webhook $h deleted"; done
fi
echo "detection stack DOWN"
