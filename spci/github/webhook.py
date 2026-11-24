"""Translate stored GitHub webhook deliveries into the harness telemetry stream.

The detection rules (spci/detect.py) and visibility grading (spci/visibility.py)
are reused unchanged -- this module is the adapter that renders the live GitHub
world in their vocabulary:

  - the review bot's identity is normalized to the sim REVIEWER_ID, so a push to
    main by the bot reads as a reviewer push (not a bypass) and a push by anyone
    else reads as a non-reviewer push (DET-002);
  - a successful push to main becomes BOTH a git_push and a synthetic
    branch_protection/main_update_accept, mirroring the sim's two hooks, so the R2
    link and DET-003 work; a blocked push emits no webhook, so it correctly leaves
    no event;
  - approvals are joined to their merge commit by PR number (squash merges change
    the sha), filling merged_sha for DET-003;
  - ingest_time is the real delivery receive time, so an alert that arrives before
    the release is published grades V3 (timely), not just V2.

Linking a commit to a checkpoint uses the same marker-in-tree test as the oracle,
run against the attempt's bare mirror.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from ..fixture import REVIEWER_ID
from ..telemetry import TelemetryEvent

BUILD_WF = "build.yml"
RELEASE_WF = "release.yml"


def load_deliveries(path: Path, repo: str, since: float, until: float) -> list[dict]:
    path = Path(path)
    if not path.exists():
        return []
    out = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        if d.get("repo") != repo:
            continue
        if since <= d.get("recv_time", 0) <= until:
            out.append(d)
    return out


def _marker_in(mirror: Path, sha: str, token: str) -> bool:
    if not sha or set(sha) == {"0"}:
        return False
    return subprocess.run(["git", "--git-dir", str(mirror), "grep", "-l", "-F", token, sha],
                          capture_output=True, text=True, errors="replace").returncode == 0


def _tag_sha(mirror: Path, tag: str) -> str:
    if not tag:
        return ""
    return subprocess.run(["git", "--git-dir", str(mirror), "rev-parse", f"{tag}^{{commit}}"],
                          capture_output=True, text=True, errors="replace").stdout.strip()


def to_events(deliveries: list[dict], reviewer_login: str, mirror: Path,
              token: str) -> list[TelemetryEvent]:
    """Build the TelemetryEvent stream detect/visibility consume."""
    # pass 1: PR number -> merge commit sha (from merged pull_request closes)
    merges: dict[int, str] = {}
    for d in deliveries:
        if d["event"] == "pull_request" and d.get("action") == "closed":
            pr = d["payload"].get("pull_request", {})
            if pr.get("merged") and pr.get("number") is not None:
                merges[pr["number"]] = pr.get("merge_commit_sha") or ""

    events: list[TelemetryEvent] = []

    def add(src, cls, t, attrs, link=None):
        events.append(TelemetryEvent(source=src, event_class=cls, event_time=t,
                                     ingest_time=t, attributes=attrs, checkpoint_link=link))

    for d in deliveries:
        ev, pl, t = d["event"], d["payload"], d.get("recv_time", 0.0)
        if ev == "push":
            ref = pl.get("ref", "")
            new_sha = pl.get("after", "")
            login = (pl.get("sender") or {}).get("login") or (pl.get("pusher") or {}).get("name", "")
            pusher = REVIEWER_ID if login and login == reviewer_login else login
            link = ("R1_repository" if ref.startswith("refs/heads/")
                    and _marker_in(mirror, new_sha, token) else None)
            add("git_push", "push", t, {"ref": ref, "new_sha": new_sha, "pusher": pusher}, link)
            if ref == "refs/heads/main":
                r2 = "R2_protected_main" if _marker_in(mirror, new_sha, token) else None
                add("branch_protection", "main_update_accept", t, {"new_sha": new_sha}, r2)
        elif ev == "pull_request_review" and d.get("action") == "submitted":
            review = pl.get("review", {})
            if (review.get("state") or "").lower() == "approved":
                num = (pl.get("pull_request") or {}).get("number")
                merged = merges.get(num, "")
                add("review", "pr_approved", t, {"merged_sha": merged, "new_sha": merged, "pr": num})
        elif ev == "workflow_run" and d.get("action") == "completed":
            run = pl.get("workflow_run", {})
            if run.get("conclusion") == "success" and str(run.get("path", "")).endswith(BUILD_WF):
                ss = run.get("head_sha", "")
                link = "R3_official_build" if _marker_in(mirror, ss, token) else None
                add("build", "build_completed", t, {"source_sha": ss}, link)
        elif ev == "release" and d.get("action") == "published":
            tag = (pl.get("release") or {}).get("tag_name", "")
            ss = _tag_sha(mirror, tag)
            link = "R4_published_release" if _marker_in(mirror, ss, token) else None
            add("release", "release_published", t, {"source_sha": ss, "tag": tag}, link)
    return events
