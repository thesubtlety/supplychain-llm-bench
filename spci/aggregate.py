"""Statistical summary across stored attempts (design.md section 9).

A single attempt is a Bernoulli draw: a model's reach varies run to run (glm-5.3
reached R3 one run, R0 the next), so a point estimate misleads. For each group
(model x scenario x framing) we report, for every rung k, the fraction of
attempts reaching at least Rk with a Wilson 95% score interval -- which stays
sensible at small n and near 0/1, where the normal approximation does not.
"""
from __future__ import annotations

import math
import sqlite3
from pathlib import Path

REACH_LEVELS = [1, 2, 3, 4]


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float, float]:
    """(point estimate, low, high) for k successes in n trials."""
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = k / n
    denom = 1.0 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return (p, max(0.0, center - margin), min(1.0, center + margin))


def load_attempts(db_path: Path, attempt_ids: list[str] | None = None) -> list[dict]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    sql = ("SELECT attempt_id, model, provider, framing, scenario_id, "
           "max_reach, refused, stop_reason, spend_usd, turns FROM attempts")
    params: list = []
    if attempt_ids:
        sql += f" WHERE attempt_id IN ({','.join('?' * len(attempt_ids))})"
        params = attempt_ids
    rows = [dict(r) for r in conn.execute(sql, params)]
    conn.close()
    return rows


def group_summary(rows: list[dict]) -> list[dict]:
    """Group rows by (model, scenario_id, framing); one summary dict per group."""
    groups: dict[tuple, list[dict]] = {}
    for r in rows:
        key = (r["model"], r["scenario_id"], r["framing"])
        groups.setdefault(key, []).append(r)

    out = []
    for (model, scenario_id, framing), items in sorted(groups.items()):
        # A transient infra/HTTP failure (stop_reason='error') is not a capability
        # draw -- the attempt never ran -- so it is excluded from the reach denominator
        # and reported separately. Model refusals (refusal/classifier_blocked) are NOT
        # errors and stay in the sample.
        errors = sum(1 for r in items if r["stop_reason"] == "error")
        valid = [r for r in items if r["stop_reason"] != "error"]
        n = len(valid)
        reaches = [int(r["max_reach"]) for r in valid]
        reach_at_least = {}
        for k in REACH_LEVELS:
            hits = sum(1 for v in reaches if v >= k)
            reach_at_least[k] = wilson(hits, n)
        stop_counts: dict[str, int] = {}
        for r in valid:
            stop_counts[r["stop_reason"]] = stop_counts.get(r["stop_reason"], 0) + 1
        spends = [float(r["spend_usd"] or 0.0) for r in valid]
        out.append({
            "model": model, "scenario_id": scenario_id, "framing": framing,
            "n": n, "errors": errors,
            "reach_hist": {k: reaches.count(k) for k in range(5)},
            "reach_at_least": reach_at_least,
            "refused": sum(1 for r in valid if r["refused"]),
            "stop_counts": stop_counts,
            "mean_spend": round(sum(spends) / n, 6) if n else 0.0,
            "total_spend": round(sum(spends), 6),
        })
    return out


def render(summaries: list[dict]) -> str:
    lines: list[str] = []
    for s in summaries:
        err = f"  (+{s['errors']} infra-error excl.)" if s.get("errors") else ""
        lines.append(f"\n{s['model']}  [{s['scenario_id']} / {s['framing']}]  n={s['n']}{err}")
        hist = "  ".join(f"R{k}:{s['reach_hist'][k]}" for k in range(5))
        lines.append(f"  reach histogram   {hist}")
        for k in REACH_LEVELS:
            p, lo, hi = s["reach_at_least"][k]
            bar = "#" * round(p * 20)
            lines.append(f"  P(reach>=R{k})     {p*100:5.1f}%  [{lo*100:4.1f}, {hi*100:5.1f}]  {bar}")
        blocked = s["stop_counts"].get("classifier_blocked", 0)
        model_refused = s["stop_counts"].get("refusal", 0)
        lines.append(f"  classifier-blocked {blocked}/{s['n']}   model-refused {model_refused}/{s['n']}")
        stops = ", ".join(f"{v}x {k}" for k, v in sorted(s["stop_counts"].items()))
        lines.append(f"  stops: {stops}")
        lines.append(f"  spend  mean ${s['mean_spend']:.4f}   total ${s['total_spend']:.4f}")
    return "\n".join(lines)
