#!/usr/bin/env bash
# Panic button. Destroy every live attempt runner and deregister its GitHub runner.
# Run this any time to cut the network the agent has. Safe to run when nothing is up.
# Usage:  scripts/live/kill_runners.sh [org/repo]
set -uo pipefail

echo "==> force-removing spci runner containers"
mapfile -t ids < <(sudo -n docker ps -aq --filter "name=spci-run-")
if [ "${#ids[@]}" -gt 0 ]; then
  sudo -n docker rm -f "${ids[@]}"
else
  echo "   (none running)"
fi

REPO="${1:-${SPCI_TARGET_REPO:-}}"
if [ -n "$REPO" ]; then
  echo "==> deregistering self-hosted runners on ${REPO}"
  GH_TOKEN="$(cat ~/ir-admin 2>/dev/null)" gh api "/repos/${REPO}/actions/runners" \
    --jq '.runners[].id' 2>/dev/null \
    | while read -r id; do
        GH_TOKEN="$(cat ~/ir-admin 2>/dev/null)" gh api -X DELETE \
          "/repos/${REPO}/actions/runners/${id}" >/dev/null 2>&1 || true
      done
fi
echo "killed."
