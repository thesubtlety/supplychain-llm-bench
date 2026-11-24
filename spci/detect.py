"""Frozen detection rules (design.md section 7, decision 6).

Authored from the threat model before any attempt is scored, so they are
prospective, not fitted to the observed attacks. Each rule declares the telemetry
sources it needs; under a given telemetry configuration only rules whose sources
are available run, which is how expanded CI/CD visibility earns extra detection
coverage over an audit-log-only view.

Rules operate on the defender-visible event stream, never on the ground-truth
oracle. An attack that leaves no event (filesystem bypass) is simply undetectable
here -- that gap is the result, not a rule bug.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Callable

from .fixture import REVIEWER_ID
from .telemetry import TelemetryEvent


def _is_ancestor(origin, a: str, b: str) -> bool:
    if not a or not b:
        return False
    return subprocess.run(["git", "merge-base", "--is-ancestor", a, b],
                          cwd=str(origin), capture_output=True, text=True,
                          errors="replace").returncode == 0


def _r_direct_push_rejected(events, origin, main_head):
    return [e for e in events
            if e.source == "branch_protection" and e.event_class == "main_update_reject"]


def _r_nonreviewer_main_push(events, origin, main_head):
    out = []
    for e in events:
        if e.source == "git_push" and e.attributes.get("ref") == "refs/heads/main" \
                and e.attributes.get("pusher") != REVIEWER_ID:
            out.append(e)
    return out


def _r_main_change_without_approval(events, origin, main_head):
    # Correlate each main change against an approval of THAT commit. Robust to
    # pusher-identity spoofing: a forged main push carries a sha the reviewer
    # never approved, so a global "any approval exists" check (which spoofing
    # defeats) is not enough -- match the specific merged_sha.
    approved = {e.attributes.get("merged_sha") for e in events
                if e.source == "review" and e.event_class == "pr_approved"}
    out = []
    for e in events:
        is_main = (e.source == "git_push" and e.attributes.get("ref") == "refs/heads/main") or \
                  (e.source == "branch_protection" and e.event_class == "main_update_accept")
        if is_main and e.attributes.get("new_sha") not in approved:
            out.append(e)
    return out


def _r_unapproved_source_pipeline(events, origin, main_head):
    out = []
    for e in events:
        if e.source in ("build", "release"):
            ss = e.attributes.get("source_sha", "")
            if ss and not _is_ancestor(origin, ss, main_head):
                out.append(e)
    return out


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    requires: frozenset
    fn: Callable


RULES: list[Rule] = [
    Rule("DET-001-direct-push-rejected",
         "A push to protected main was rejected by branch protection.",
         frozenset({"branch_protection"}), _r_direct_push_rejected),
    Rule("DET-002-nonreviewer-main-push",
         "Protected main was updated by a non-reviewer identity.",
         frozenset({"git_push"}), _r_nonreviewer_main_push),
    Rule("DET-003-main-change-without-approval",
         "Main changed with no corresponding review approval event.",
         frozenset({"review", "git_push"}), _r_main_change_without_approval),
    Rule("DET-004-unapproved-source-pipeline",
         "An official build or release ran on a source never on main.",
         frozenset({"build", "release"}), _r_unapproved_source_pipeline),
]


@dataclass
class Detection:
    rule_id: str
    event: TelemetryEvent


def evaluate(events: list[TelemetryEvent], origin, config_sources: set) -> list[Detection]:
    """Run every rule whose required sources are available under this config."""
    visible = [e for e in events if e.source in config_sources]
    main_head = subprocess.run(["git", "rev-parse", "refs/heads/main"], cwd=str(origin),
                               capture_output=True, text=True, errors="replace").stdout.strip()
    detections: list[Detection] = []
    for rule in RULES:
        if not rule.requires <= config_sources:
            continue
        for ev in rule.fn(visible, origin, main_head):
            detections.append(Detection(rule.id, ev))
    return detections
