"""SQLite store for the three linked tables (design.md section 10).

attempts (one per run), outcomes (one per evaluated checkpoint/side-outcome),
telemetry (one per defender-visible event). A thin subset of the full field list,
enough for the R0->R1 slice; columns are additive as later phases land.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS attempts (
    attempt_id TEXT PRIMARY KEY,
    model TEXT, provider TEXT, framing TEXT,
    scenario_id TEXT, scenario_seed TEXT, harness_version TEXT,
    budget_usd REAL, spend_usd REAL, turns INTEGER, wall_clock REAL,
    max_reach INTEGER, refused INTEGER, stop_reason TEXT, created_at REAL
);
CREATE TABLE IF NOT EXISTS outcomes (
    attempt_id TEXT, checkpoint_id TEXT, outcome_family TEXT, status TEXT,
    verified_at REAL, oracle_evidence TEXT, control_status TEXT,
    visibility_a TEXT, visibility_b TEXT,
    FOREIGN KEY(attempt_id) REFERENCES attempts(attempt_id)
);
CREATE TABLE IF NOT EXISTS telemetry (
    attempt_id TEXT, source TEXT, event_class TEXT,
    event_time REAL, ingest_time REAL, checkpoint_link TEXT,
    attributes TEXT, rule_id TEXT, rule_match INTEGER, alert_time REAL,
    FOREIGN KEY(attempt_id) REFERENCES attempts(attempt_id)
);
"""


class Store:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.executescript(SCHEMA)
        self._migrate()
        self.conn.commit()

    def _migrate(self) -> None:
        """Add columns introduced after a store was first created. CREATE TABLE
        IF NOT EXISTS does not alter an existing table, so reopening an older db
        needs these."""
        wanted = {"outcomes": [("visibility_a", "TEXT"), ("visibility_b", "TEXT")]}
        for table, cols in wanted.items():
            existing = {r[1] for r in self.conn.execute(f"PRAGMA table_info({table})")}
            for name, decl in cols:
                if name not in existing:
                    self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")

    def write_attempt(self, row: dict) -> None:
        cols = ("attempt_id model provider framing scenario_id scenario_seed "
                "harness_version budget_usd spend_usd turns wall_clock max_reach "
                "refused stop_reason created_at").split()
        self.conn.execute(
            f"INSERT OR REPLACE INTO attempts ({','.join(cols)}) VALUES ({','.join('?'*len(cols))})",
            [row.get(c) for c in cols],
        )
        self.conn.commit()

    def write_outcome(self, row: dict) -> None:
        cols = ("attempt_id checkpoint_id outcome_family status verified_at "
                "oracle_evidence control_status visibility_a visibility_b").split()
        r = dict(row)
        if isinstance(r.get("oracle_evidence"), (dict, list)):
            r["oracle_evidence"] = json.dumps(r["oracle_evidence"])
        self.conn.execute(
            f"INSERT INTO outcomes ({','.join(cols)}) VALUES ({','.join('?'*len(cols))})",
            [r.get(c) for c in cols],
        )
        self.conn.commit()

    def write_telemetry(self, row: dict) -> None:
        cols = ("attempt_id source event_class event_time ingest_time "
                "checkpoint_link attributes rule_id rule_match alert_time").split()
        r = dict(row)
        if isinstance(r.get("attributes"), (dict, list)):
            r["attributes"] = json.dumps(r["attributes"])
        self.conn.execute(
            f"INSERT INTO telemetry ({','.join(cols)}) VALUES ({','.join('?'*len(cols))})",
            [r.get(c) for c in cols],
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()
