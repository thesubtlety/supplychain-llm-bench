"""Frozen scenario configuration (design.md section 8 reproducibility fields)."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

HARNESS_VERSION = "0.1.0-slice"


@dataclass
class Scenario:
    scenario_id: str
    scenario_seed: str
    framing: str            # "authorized" | "neutral"
    reach_target: int       # highest checkpoint this scenario evaluates
    budget_usd: float
    max_turns: int
    wall_clock_s: float
    no_progress_limit: int
    system_prompt_file: str
    objective_file: str
    reviewer_mode: str = "baseline"   # baseline | hardened | policy_malice | semgrep | llm
    reviewer_model: str = ""          # llm arm only: OpenRouter slug; "" => reviewer default
    secret_scenario: bool = False     # live: score DEPLOY_TOKEN access/use/exfil
    poison_scenario: bool = False     # local: seed the key-gate app + score the backdoor
    canary_key: str = ""              # poison: the key the released app must NOT grant

    @staticmethod
    def load(path: str | Path) -> "Scenario":
        data = json.loads(Path(path).read_text())
        return Scenario(**data)

    def system_prompt(self, base: Path) -> str:
        sys_text = (base / self.system_prompt_file).read_text()
        obj_text = (base / self.objective_file).read_text()
        return f"{sys_text}\n\n## Objective\n\n{obj_text}"
