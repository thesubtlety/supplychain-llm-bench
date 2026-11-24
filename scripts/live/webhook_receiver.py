"""GitHub webhook receiver -> the defender-visible event stream for live runs.

Long-lived process. Verifies each delivery's HMAC signature (fail closed), then
appends it with its receive time to a JSONL file. LiveEpisode reads that file for
the attempt's time window and translates deliveries into the same telemetry the
detection rules already consume (spci/github/webhook.py).

GitHub must be able to reach this. On a Tailscale-only box, expose it with a tunnel
(smee.io or `cloudflared tunnel --url http://localhost:8899`) and point the repo's
webhook at that public URL with the same secret.

  SPCI_WEBHOOK_SECRET=<secret> python3 scripts/live/webhook_receiver.py
Env: SPCI_WEBHOOK_PORT (8899), SPCI_WEBHOOKS_FILE (runs-live/webhooks.jsonl).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SECRET = os.environ.get("SPCI_WEBHOOK_SECRET", "").encode()
OUT = Path(os.environ.get("SPCI_WEBHOOKS_FILE", "runs-live/webhooks.jsonl"))
PORT = int(os.environ.get("SPCI_WEBHOOK_PORT", "8899"))


def _valid(body: bytes, sig: str) -> bool:
    """Constant-time HMAC check. Fail closed: no secret or no/!matching sig -> drop."""
    if not SECRET or not sig or not sig.startswith("sha256="):
        return False
    mac = hmac.new(SECRET, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest("sha256=" + mac, sig)


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        if not _valid(body, self.headers.get("X-Hub-Signature-256", "")):
            self.send_response(401)
            self.end_headers()
            return
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            return
        rec = {
            "recv_time": time.time(),
            "delivery": self.headers.get("X-GitHub-Delivery", ""),
            "event": self.headers.get("X-GitHub-Event", ""),
            "repo": (payload.get("repository") or {}).get("full_name", ""),
            "action": payload.get("action", ""),
            "payload": payload,
        }
        OUT.parent.mkdir(parents=True, exist_ok=True)
        with OUT.open("a") as fh:
            fh.write(json.dumps(rec) + "\n")
        self.send_response(204)
        self.end_headers()

    def do_GET(self):   # health check
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def main() -> None:
    if not SECRET:
        raise SystemExit("set SPCI_WEBHOOK_SECRET (deliveries are rejected without it)")
    print(f"webhook receiver on :{PORT} -> {OUT}")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
