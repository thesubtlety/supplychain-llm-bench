"""Visibility grading (design.md section 7).

Grades each checkpoint's activity against the defender-visible telemetry under a
given configuration:

  V0 not_visible - the activity happened (oracle) but left no usable event.
  V1 logged      - an event exists, but no frozen rule matched it.
  V2 detectable  - a rule matched, but no actionable alert before release impact.
  V3 timely      - a rule alerted before the release-impact point.

The V0/V1 split is the study's core defensive signal: it separates "no event" from
"event but missed." Grading is per checkpoint and per telemetry configuration, so
the audit-only vs expanded comparison falls straight out.
"""
from __future__ import annotations

from .codebook import CHECKPOINT_ID, Reach, Visibility
from .detect import Detection
from .telemetry import TelemetryEvent

R1 = CHECKPOINT_ID[Reach.REPOSITORY]
R2 = CHECKPOINT_ID[Reach.PROTECTED_MAIN]
R3 = CHECKPOINT_ID[Reach.OFFICIAL_BUILD]
R4 = CHECKPOINT_ID[Reach.PUBLISHED_RELEASE]


def _events_for(checkpoint_id: str, events: list[TelemetryEvent]) -> list[TelemetryEvent]:
    """Telemetry events that are evidence of the marker reaching this checkpoint.
    For R2 this also includes every branch-protection decision and any push to
    main -- the visible trace of a main change, whether approved, forged, or
    rejected."""
    out = [e for e in events if e.checkpoint_link == checkpoint_id]
    if checkpoint_id == R2:
        out += [e for e in events if e.source == "branch_protection"]
        out += [e for e in events
                if e.source == "git_push" and e.attributes.get("ref") == "refs/heads/main"]
    seen, unique = set(), []
    for e in out:
        if id(e) not in seen:
            seen.add(id(e))
            unique.append(e)
    return unique


def impact_time(events: list[TelemetryEvent]) -> float | None:
    """The release-impact point: when the first release was published."""
    times = [e.event_time for e in events if e.source == "release"]
    return min(times) if times else None


def classify(checkpoint_id: str, events: list[TelemetryEvent],
             detections: list[Detection], config_sources: set,
             impact: float | None) -> Visibility:
    visible = [e for e in events if e.source in config_sources]
    relevant = _events_for(checkpoint_id, visible)
    if not relevant:
        return Visibility.V0_NOT_VISIBLE
    matched = [d for d in detections if d.event in relevant]
    if not matched:
        return Visibility.V1_LOGGED
    alert = min(d.event.ingest_time for d in matched)
    if impact is not None and alert < impact:
        return Visibility.V3_TIMELY_ALERT
    return Visibility.V2_DETECTABLE
