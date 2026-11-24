"""Metered inference cost and the hard per-attempt budget.

Prices are USD per million tokens, first-party Anthropic API rates (claude-api
skill, cached 2026-11-03). Provider adapters report raw token usage; the meter
turns that into dollars and enforces the cap. Pricing is a frozen snapshot per
the reproducibility requirement in design.md section 8.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# model_id -> (input, output, cache_write_5m, cache_read) USD per 1M tokens.
# cache_write/read default to input/‑ when a model's rates are not separately
# tracked here; extend as the roster grows.
PRICING: dict[str, tuple[float, float, float, float]] = {
    "claude-haiku-5-5": (0.10, 0.50, 0.125, 0.01),
    "claude-sonnet-5-5": (2.00, 10.00, 2.50, 0.10),
    "claude-opus-5-5": (4.00, 20.00, 5.00, 0.20),
    "claude-fable-5-2": (8.00, 40.00, 10.00, 0.20),
    # Scripted/mock provider: free, so the meter exercises without real spend.
    "scripted": (0.0, 0.0, 0.0, 0.0),
}

PRICING_SNAPSHOT = "2026-11-03"


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0

    def __add__(self, other: "Usage") -> "Usage":
        return Usage(
            self.input_tokens + other.input_tokens,
            self.output_tokens + other.output_tokens,
            self.cache_creation_input_tokens + other.cache_creation_input_tokens,
            self.cache_read_input_tokens + other.cache_read_input_tokens,
        )


class UnknownModelError(KeyError):
    pass


def cost_usd(model: str, usage: Usage) -> float:
    try:
        pin, pout, pcw, pcr = PRICING[model]
    except KeyError as e:
        raise UnknownModelError(model) from e
    return (
        usage.input_tokens * pin
        + usage.output_tokens * pout
        + usage.cache_creation_input_tokens * pcw
        + usage.cache_read_input_tokens * pcr
    ) / 1_000_000.0


@dataclass
class CostMeter:
    model: str
    budget_usd: float
    spend_usd: float = 0.0
    total: Usage = field(default_factory=Usage)
    unmetered_turns: int = 0

    def charge(self, usage: Usage, actual_cost: float | None = None) -> float:
        """Charge a turn. Prefer the provider's actual billed cost (e.g. OpenRouter
        `usage.cost`); otherwise price the tokens from the frozen table.

        A provider-billed model with no cost on this turn (a transient OpenRouter
        response missing `usage.cost`) must not crash the run: count it as
        unmetered and charge 0 rather than raising UnknownModelError on a slug the
        price table never covers."""
        if actual_cost is not None:
            c = actual_cost
        else:
            try:
                c = cost_usd(self.model, usage)
            except UnknownModelError:
                c = 0.0
                self.unmetered_turns += 1
        self.spend_usd += c
        self.total = self.total + usage
        return c

    @property
    def exhausted(self) -> bool:
        return self.spend_usd >= self.budget_usd
