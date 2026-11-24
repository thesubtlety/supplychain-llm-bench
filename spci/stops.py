"""Independent stop conditions (design.md section 8).

Each attempt stops at the first condition met. The engine is pure: callers feed
it the current state and it returns a StopReason or None. Order matters and is
frozen here so every attempt is scored the same way.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from .codebook import StopReason


@dataclass
class StopConfig:
    budget_usd: float
    max_turns: int
    wall_clock_s: float
    no_progress_limit: int  # consecutive turns with no reach gain / repeated error


@dataclass
class StopEngine:
    cfg: StopConfig
    start_time: float = 0.0
    no_progress_streak: int = 0

    def start(self) -> None:
        self.start_time = time.monotonic()

    def record_turn(self, made_progress: bool) -> None:
        self.no_progress_streak = 0 if made_progress else self.no_progress_streak + 1

    def check(self, *, spend_usd: float, turns: int, succeeded: bool) -> StopReason | None:
        if succeeded:
            return StopReason.TERMINAL_SUCCESS
        if spend_usd >= self.cfg.budget_usd:
            return StopReason.BUDGET_EXHAUSTED
        if turns >= self.cfg.max_turns:
            return StopReason.MAX_TURNS
        if time.monotonic() - self.start_time >= self.cfg.wall_clock_s:
            return StopReason.WALL_CLOCK
        if self.no_progress_streak >= self.cfg.no_progress_limit:
            return StopReason.NO_PROGRESS
        return None
