"""Real Anthropic adapter over the raw Messages API (no SDK dependency).

Calls POST /v1/messages with urllib so the harness stays dependency-free and the
cost meter reads provider `usage` directly. Current models think adaptively, so
no `thinking`/sampling params are sent (api version 2026-10-21 rejects them).
`stop_reason == "refusal"` is surfaced as a terminal refusal.

Not exercised in the thin slice (no key in the environment); it is drop-in once
ANTHROPIC_API_KEY is set and the runner is containerized.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from ..cost import Usage
from .base import AgentStep, ToolCall

API_URL = "https://api.anthropic.com/v1/messages"
API_VERSION = "2026-10-21"


class AnthropicProvider:
    def __init__(self, model: str, *, max_tokens: int = 4096, effort: str | None = None,
                 api_key: str | None = None, timeout_s: float = 120.0):
        self.model = model
        self.max_tokens = max_tokens
        self.effort = effort
        self.timeout_s = timeout_s
        self._key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self._key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")

    def step(self, system, messages, tools) -> AgentStep:
        body = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system,
            "messages": messages,
            "tools": tools,
        }
        if self.effort:
            body["output_config"] = {"effort": self.effort}
        req = urllib.request.Request(
            API_URL, data=json.dumps(body).encode(), method="POST",
            headers={
                "content-type": "application/json",
                "x-api-key": self._key,
                "anthropic-version": API_VERSION,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return AgentStep([], [], Usage(), "error", error=f"HTTP {e.code}: {e.read().decode()[:500]}")
        except urllib.error.URLError as e:
            return AgentStep([], [], Usage(), "error", error=str(e))

        u = data.get("usage", {})
        usage = Usage(
            input_tokens=u.get("input_tokens", 0),
            output_tokens=u.get("output_tokens", 0),
            cache_creation_input_tokens=u.get("cache_creation_input_tokens", 0),
            cache_read_input_tokens=u.get("cache_read_input_tokens", 0),
        )
        content = data.get("content", [])
        stop_reason = data.get("stop_reason", "end_turn")
        tool_calls = [
            ToolCall(b["id"], b["name"], b.get("input", {}))
            for b in content if b.get("type") == "tool_use"
        ]
        text = "".join(b.get("text", "") for b in content if b.get("type") == "text")
        return AgentStep(
            content, tool_calls, usage, stop_reason,
            refused=(stop_reason == "refusal"), text=text,
        )
