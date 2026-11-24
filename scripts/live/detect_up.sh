#!/usr/bin/env bash
# Bring up the detection stack in one command: webhook receiver + cloudflared quick
# tunnel + repo webhook pointed at the (ephemeral) tunnel URL. Idempotent: reuses a
# persisted HMAC secret, (re)starts the receiver/tunnel if down, and UPDATES the
# existing repo webhook to the current URL (quick-tunnel URLs change each restart).
# Usage:  SPCI_TARGET_REPO=org/repo scripts/live/detect_up.sh
set -uo pipefail
SLUG="${SPCI_TARGET_REPO:?set SPCI_TARGET_REPO=<org>/<repo>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
STATE="${SPCI_DETECT_STATE:-$HOME/.config/spci}"; mkdir -p "$STATE"; chmod 700 "$STATE"
PORT="${SPCI_WEBHOOK_PORT:-8899}"
WEBHOOKS_FILE="${SPCI_WEBHOOKS_FILE:-$ROOT/runs-live/webhooks.jsonl}"
SECRET_FILE="$STATE/webhook_secret"
A() { GH_TOKEN="${SPCI_GH_ADMIN_TOKEN:-$(cat ~/ir-admin)}" gh api "$@"; }

[ -s "$SECRET_FILE" ] || { openssl rand -hex 16 > "$SECRET_FILE"; chmod 600 "$SECRET_FILE"; }

if ! pgrep -f 'webhook_receiver[.]py' >/dev/null; then
  SPCI_WEBHOOK_SECRET=$(cat "$SECRET_FILE") SPCI_WEBHOOK_PORT=$PORT SPCI_WEBHOOKS_FILE="$WEBHOOKS_FILE" \
    nohup python3 "$HERE/webhook_receiver.py" >"$STATE/receiver.log" 2>&1 &
  echo "receiver started (:$PORT -> $WEBHOOKS_FILE)"
else echo "receiver already running"; fi

if ! pgrep -f 'cloudflared tunnel' >/dev/null; then
  : > "$STATE/cloudflared.out"
  nohup cloudflared tunnel --url "http://localhost:$PORT" >"$STATE/cloudflared.out" 2>&1 &
  echo "tunnel starting..."
fi

URL=""
for _ in $(seq 1 25); do
  URL=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$STATE/cloudflared.out" 2>/dev/null | head -1)
  [ -n "$URL" ] && break; sleep 1
done
[ -n "$URL" ] || { echo "tunnel URL not ready; see $STATE/cloudflared.out"; exit 1; }
echo "$URL" > "$STATE/tunnel_url"
# The URL prints before the edge/DNS is fully resolvable, so retry the health check.
HEALTH=""
for _ in $(seq 1 15); do
  curl -fsS --max-time 10 "$URL" >/dev/null 2>&1 && { HEALTH=ok; break; }
  sleep 2
done
[ "$HEALTH" = ok ] && echo "tunnel: $URL (health ok)" \
  || { echo "tunnel not reaching receiver after retries; see $STATE/cloudflared.out"; exit 1; }

python3 -c "import json;json.dump({'name':'web','active':True,'events':['push','pull_request','pull_request_review','workflow_run','release'],'config':{'url':'$URL','content_type':'json','secret':open('$SECRET_FILE').read().strip()}},open('$STATE/hook.json','w'))"
chmod 600 "$STATE/hook.json"
HID=$(A "/repos/$SLUG/hooks" --jq '.[0].id' 2>/dev/null)
if [ -n "$HID" ] && [ "$HID" != "null" ]; then
  A -X PATCH "/repos/$SLUG/hooks/$HID" --input "$STATE/hook.json" >/dev/null && echo "webhook $HID updated -> $URL"
else
  A -X POST "/repos/$SLUG/hooks" --input "$STATE/hook.json" --jq '.id' | xargs echo "webhook created:"
fi
rm -f "$STATE/hook.json"
echo "detection stack UP"
