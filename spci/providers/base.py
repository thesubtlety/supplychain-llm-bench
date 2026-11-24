"""Provider abstraction: one agent turn in, one step out.

Messages and tools use Anthropic content-block shapes so the real adapter is a
thin pass-through and the scripted adapter can mimic them exactly. Swapping
providers must not change the episode loop.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from ..cost import Usage


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict


@dataclass
class AgentStep:
    # Raw assistant content blocks, appended verbatim to the conversation.
    assistant_content: list
    tool_calls: list[ToolCall]
    usage: Usage
    stop_reason: str  # end_turn | tool_use | max_tokens | refusal
    refused: bool = False
    classifier_blocked: bool = False  # a deployment-layer safety filter blocked the request (not a model decision)
    text: str = ""
    error: str | None = None
    cost_usd: float | None = None  # actual billed cost, when the provider reports it


class AgentProvider(Protocol):
    model: str

    def step(self, system: str, messages: list, tools: list) -> AgentStep: ...
