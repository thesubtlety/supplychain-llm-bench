#!/usr/bin/env bash
# Per-attempt reset: force main back to the pristine pipeline commit and clear all
# attempt debris (open PRs, releases, tags, feature branches). Keeps main + pristine.
#
# main is protected, so this temporarily DISABLES the protect-main ruleset to force
# the ref, then RE-ENABLES it via an EXIT trap -- so main is never left unprotected,
# even if a step fails. Run between attempts (the batch loop calls it automatically).
# Usage:  SPCI_TARGET_REPO=org/repo scripts/live/reset_repo.sh
set -uo pipefail
SLUG="${SPCI_TARGET_REPO:?set SPCI_TARGET_REPO=<org>/<repo>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
A() { GH_TOKEN="${SPCI_GH_ADMIN_TOKEN:-$(cat ~/ir-admin 2>/dev/null)}" gh api "$@"; }
# Toggle enforcement on the SAME ruleset the repo was bootstrapped with, so the
# secret scenario's bypass_actors are never clobbered by the plain ruleset.
RULESET_FILE="${SPCI_RULESET_FILE:-$HERE/ruleset.json}"
_rule() { python3 -c "import json,sys;d=json.load(open('$RULESET_FILE'));d['enforcement']='$1';json.dump(d,sys.stdout)"; }

RID=$(A "/repos/$SLUG/rulesets" --jq '.[]|select(.name=="protect-main").id' 2>/dev/null | head -1)
# Canonical pristine SHA: prefer the out-of-band value (SPCI_PRISTINE_SHA) over the
# live 'pristine' branch, which an attempt can poison (the branch is now ruleset-
# protected, but we still RESTORE it each reset as belt-and-suspenders). Without the
# env override we fall back to the branch SHA (back-compat for non-secret repos).
PRISTINE="${SPCI_PRISTINE_SHA:-$(A "/repos/$SLUG/git/refs/heads/pristine" --jq '.object.sha' 2>/dev/null)}"
[ -n "$PRISTINE" ] || { echo "no 'pristine' branch -- run bootstrap_repo.sh first"; exit 1; }

reenable() { [ -n "$RID" ] && _rule active | A -X PUT "/repos/$SLUG/rulesets/$RID" --input - >/dev/null 2>&1 && echo "ruleset re-enabled"; }
trap reenable EXIT

[ -n "$RID" ] && _rule disabled | A -X PUT "/repos/$SLUG/rulesets/$RID" --input - >/dev/null
# Restore the pristine anchor itself first (undo any poisoning), then force main to it.
A -X PATCH "/repos/$SLUG/git/refs/heads/pristine" -f sha="$PRISTINE" -F force=true >/dev/null 2>&1
A -X PATCH "/repos/$SLUG/git/refs/heads/main" -f sha="$PRISTINE" -F force=true >/dev/null
echo "main + pristine forced to canonical ($PRISTINE)"

A "/repos/$SLUG/pulls?state=open&per_page=100" --jq '.[].number' 2>/dev/null \
  | while read -r n; do A -X PATCH "/repos/$SLUG/pulls/$n" -f state=closed >/dev/null; done
A "/repos/$SLUG/releases?per_page=100" --jq '.[].id' 2>/dev/null \
  | while read -r id; do A -X DELETE "/repos/$SLUG/releases/$id" >/dev/null; done
A "/repos/$SLUG/git/matching-refs/tags" --jq '.[].ref' 2>/dev/null \
  | while read -r r; do A -X DELETE "/repos/$SLUG/git/$r" >/dev/null; done
A "/repos/$SLUG/branches?per_page=100" --jq '.[].name' 2>/dev/null \
  | grep -vxE 'main|pristine' \
  | while read -r b; do A -X DELETE "/repos/$SLUG/git/refs/heads/$b" >/dev/null || true; done

echo "reset complete: $SLUG"
# EXIT trap re-enables the ruleset
