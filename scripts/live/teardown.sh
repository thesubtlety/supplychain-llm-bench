#!/usr/bin/env bash
# Reset a target repo between attempts: delete non-main branches, PRs, tags,
# releases, and leftover self-hosted runners. Keeps the guarded pipeline on main.
# Usage:  scripts/live/teardown.sh <org> <repo>
set -euo pipefail
SLUG="${SPCI_TARGET_REPO:-}"
if [ -n "${1:-}" ] && [ -n "${2:-}" ]; then SLUG="$1/$2"; fi
: "${SLUG:?set SPCI_TARGET_REPO=<org>/auto-spci-bench or pass <org> <repo>}"
GH() { GH_TOKEN="${SPCI_GH_ADMIN_TOKEN:-$(cat ~/ir-admin 2>/dev/null)}" gh "$@"; }

echo "==> close open PRs"
GH api "/repos/${SLUG}/pulls?state=open&per_page=100" --jq '.[].number' \
  | while read -r n; do GH api -X PATCH "/repos/${SLUG}/pulls/${n}" -f state=closed >/dev/null; done

echo "==> delete releases + tags"
GH api "/repos/${SLUG}/releases?per_page=100" --jq '.[].id' \
  | while read -r id; do GH api -X DELETE "/repos/${SLUG}/releases/${id}" >/dev/null; done
GH api "/repos/${SLUG}/git/matching-refs/tags" --jq '.[].ref' \
  | while read -r ref; do GH api -X DELETE "/repos/${SLUG}/git/${ref}" >/dev/null; done

echo "==> delete non-main branches"
GH api "/repos/${SLUG}/branches?per_page=100" --jq '.[].name' \
  | grep -vxE 'main|pristine' \
  | while read -r b; do GH api -X DELETE "/repos/${SLUG}/git/refs/heads/${b}" >/dev/null || true; done

echo "==> remove any lingering self-hosted runners"
GH api "/repos/${SLUG}/actions/runners" --jq '.runners[].id' 2>/dev/null \
  | while read -r id; do GH api -X DELETE "/repos/${SLUG}/actions/runners/${id}" >/dev/null || true; done

echo "reset: ${SLUG}"
