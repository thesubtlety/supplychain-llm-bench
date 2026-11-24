"""OpenRouter adapter over the raw chat-completions API (no SDK dependency).

OpenRouter exposes one OpenAI-compatible endpoint across many models, so the whole
roster is reachable by changing the `model` slug (e.g. `z-ai/glm-5.3`). Every
response carries `usage.cost` (actual billed amount, USD), so the cost meter uses
real spend rather than a per-model price table -- which matters for a roster that
cycles through dozens of models.

Tool calling is OpenAI-format: `tools[].function`, assistant `tool_calls[]` whose
`function.arguments` is a JSON string, and `role:"tool"` results keyed by
`tool_call_id`. The harness speaks Anthropic content-block shapes internally, so
this adapter translates both directions.

Not exercised without OPENROUTER_API_KEY; pair it with the docker runner before
driving real shell.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

RETRYABLE_HTTP = {408, 409, 429, 500, 502, 503, 504}
MAX_RETRIES = 3

from ..cost import Usage
from ..runner import TOOL_NAME
from .base import AgentStep, ToolCall

API_URL = "https://openrouter.ai/api/v1/chat/completions"
KEY_FILE = Path.home() / "or"  # fallback key location, kept outside the repo


def _read_key(explicit: str | None) -> str | None:
    if explicit:
        return explicit.strip()
    env = os.environ.get("OPENROUTER_API_KEY")
    if env:
        return env.strip()
    try:
        return KEY_FILE.read_text().strip() or None
    except OSError:
        return None


def _tools_openai(anthropic_tools: list) -> list:
    out = []
    for t in anthropic_tools:
        out.append({"type": "function", "function": {
            "name": t["name"], "description": t.get("description", ""),
            "parameters": t["input_schema"],
        }})
    return out


def _messages_openai(system: str, messages: list) -> list:
    """Translate the harness's Anthropic-shaped messages to OpenAI chat messages."""
    out = [{"role": "system", "content": system}]
    for m in messages:
        role, content = m["role"], m["content"]
        if isinstance(content, str):
            out.append({"role": role, "content": content})
            continue
        if role == "assistant":
            text = "".join(b.get("text", "") for b in content if b.get("type") == "text")
            tool_calls = [{
                "id": b["id"], "type": "function",
                "function": {"name": b["name"], "arguments": json.dumps(b.get("input", {}))},
            } for b in content if b.get("type") == "tool_use"]
            msg = {"role": "assistant", "content": text or None}
            if tool_calls:
                msg["tool_calls"] = tool_calls
            out.append(msg)
        else:  # user turn: plain text and/or tool_result blocks
            results = [b for b in content if b.get("type") == "tool_result"]
            text = "".join(b.get("text", "") for b in content if b.get("type") == "text")
            if text:
                out.append({"role": "user", "content": text})
            for b in results:
                out.append({"role": "tool", "tool_call_id": b["tool_use_id"],
                            "content": b.get("content", "")})
    return out


def oneshot(model: str, system: str, user: str, *, max_tokens: int = 800,
            timeout_s: float = 120.0, api_key: str | None = None) -> tuple[str, float | None]:
    """One-shot chat completion with no tools, for the v2 LLM-reviewer arm. Returns
    (text, cost_usd); cost is None when the provider omits it. Reuses the endpoint,
    key resolution and retry policy. Raises RuntimeError on missing key or a
    non-retryable/exhausted failure so the caller can fail closed."""
    key = _read_key(api_key)
    if not key:
        raise RuntimeError("OpenRouter key not found (set OPENROUTER_API_KEY or write it to ~/or)")
    body = {"model": model, "max_tokens": max_tokens,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}]}
    req = urllib.request.Request(
        API_URL, data=json.dumps(body).encode(), method="POST",
        headers={"content-type": "application/json", "authorization": f"Bearer {key}"})
    last_err = None
    data = None
    for attempt in range(MAX_RETRIES):
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                data = json.loads(resp.read())
            break
        except urllib.error.HTTPError as e:
            last_err = f"HTTP {e.code}: {e.read().decode()[:300]}"
            if e.code not in RETRYABLE_HTTP or attempt == MAX_RETRIES - 1:
                raise RuntimeError(last_err)
        except urllib.error.URLError as e:
            last_err = str(e)
            if attempt == MAX_RETRIES - 1:
                raise RuntimeError(last_err)
        time.sleep(1.5 * (attempt + 1))
    if data is None:
        raise RuntimeError(last_err or "no response")
    if data.get("error"):
        raise RuntimeError(str(data["error"])[:300])
    choice = (data.get("choices") or [{}])[0]
    msg = choice.get("message") or {}
    refusal = msg.get("refusal")
    # A safety-classifier block comes back as finish_reason=content_filter and/or a
    # `refusal` string. Surface it as an error so the caller fails closed instead of
    # mistaking the refusal prose for a verdict.
    if choice.get("finish_reason") == "content_filter" or refusal:
        raise RuntimeError(f"refused: {str(refusal or 'content_filter')[:200]}")
    text = msg.get("content") or ""
    cost = (data.get("usage") or {}).get("cost")
    return text, cost


class OpenRouterProvider:
    def __init__(self, model: str, *, max_tokens: int = 4096,
                 api_key: str | None = None, timeout_s: float = 180.0):
        self.model = model
        self.max_tokens = max_tokens
        self.timeout_s = timeout_s
        self._key = _read_key(api_key)
        if not self._key:
            raise RuntimeError(f"OpenRouter key not found (set OPENROUTER_API_KEY or write it to {KEY_FILE})")

    def step(self, system, messages, tools) -> AgentStep:
        body = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": _messages_openai(system, messages),
            "tools": _tools_openai(tools),
            "tool_choice": "auto",
        }
        req = urllib.request.Request(
            API_URL, data=json.dumps(body).encode(), method="POST",
            headers={"content-type": "application/json",
                     "authorization": f"Bearer {self._key}"},
        )
        # Transient errors are expected across a long roster run; retry a few
        # times with linear backoff before surfacing the error as a stop.
        data = None
        last_err = None
        for attempt in range(MAX_RETRIES):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                    data = json.loads(resp.read())
                break
            except urllib.error.HTTPError as e:
                last_err = f"HTTP {e.code}: {e.read().decode()[:500]}"
                if e.code not in RETRYABLE_HTTP or attempt == MAX_RETRIES - 1:
                    return AgentStep([], [], Usage(), "error", error=last_err)
            except urllib.error.URLError as e:
                last_err = str(e)
                if attempt == MAX_RETRIES - 1:
                    return AgentStep([], [], Usage(), "error", error=last_err)
            time.sleep(1.5 * (attempt + 1))
        if data is None:
            return AgentStep([], [], Usage(), "error", error=last_err or "no response")

        if data.get("error"):
            return AgentStep([], [], Usage(), "error", error=str(data["error"])[:500])

        u = data.get("usage") or {}
        usage = Usage(
            input_tokens=u.get("prompt_tokens", 0),
            output_tokens=u.get("completion_tokens", 0),
            cache_read_input_tokens=(u.get("prompt_tokens_details") or {}).get("cached_tokens", 0),
        )
        cost = u.get("cost")  # actual billed USD; None on some providers
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        finish = choice.get("finish_reason", "stop")

        content_blocks: list = []
        text = msg.get("content") or ""
        if text:
            content_blocks.append({"type": "text", "text": text})
        tool_calls = []
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function", {})
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            tool_calls.append(ToolCall(tc["id"], fn.get("name", TOOL_NAME), args))
            content_blocks.append({"type": "tool_use", "id": tc["id"],
                                   "name": fn.get("name", TOOL_NAME), "input": args})

        # A safety-classifier block (e.g. Anthropic Cyber safeguards) comes back as
        # finish_reason=content_filter with the reason in `message.refusal` and often
        # no usage/cost. Capture that text so a refusal's NATURE is recoverable --
        # a deployment-layer block is not the same as a model's in-context decline.
        refusal_text = msg.get("refusal") or ""
        blocked = finish == "content_filter" or bool(refusal_text)
        return AgentStep(content_blocks, tool_calls, usage, finish,
                         refused=blocked, classifier_blocked=blocked,
                         text=text or refusal_text,
                         cost_usd=cost if cost is not None else None)
