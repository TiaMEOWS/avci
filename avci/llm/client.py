"""LLM client: vendor-agnostic, LiteLLM-first, OpenAI-compatible fallback.

`provider=litellm` routes through the litellm library, which normalizes
tool calling across vendors — Claude (ANTHROPIC_API_KEY), GPT
(OPENAI_API_KEY), DeepSeek (DEEPSEEK_API_KEY), Kimi (MOONSHOT_API_KEY),
Gemini, GLM, Qwen, Ollama... the model string picks the vendor. When
`base_url` is set (LiteLLM proxy, OpenRouter, Ollama, vLLM, any
OpenAI-compatible gateway) bare model names are wrapped as `openai/<model>`
so the gateway routes them. `provider=openai` talks straight to base_url
with the OpenAI SDK.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("avci.llm")


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class LLMResponse:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    finish_reason: str = ""
    usage: dict[str, int] = field(default_factory=dict)


class LLMClient:
    def __init__(self, settings) -> None:
        self.s = settings
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self._openai_client = None
        if self.s.provider == "openai":
            from openai import OpenAI  # type: ignore
            kw: dict[str, Any] = {"timeout": self.s.request_timeout}
            if self.s.base_url:
                kw["base_url"] = self.s.base_url
            if self.s.api_key:
                kw["api_key"] = self.s.api_key
            self._openai_client = OpenAI(**kw)

    # ------------------------------------------------------------------
    def chat(self, messages: list[dict], tools: list[dict] | None = None) -> LLMResponse:
        last_err: Exception | None = None
        for attempt in range(6):
            try:
                return self._chat_once(messages, tools)
            except Exception as exc:  # noqa: BLE001 — retry any transport error
                last_err = exc
                backoff = min(2 ** attempt * 2, 30)
                log.warning("LLM call failed (%s), retry in %ss", exc, backoff)
                time.sleep(backoff)
        raise RuntimeError(f"LLM unreachable after retries: {last_err}")

    def _chat_once(self, messages: list[dict], tools: list[dict] | None) -> LLMResponse:
        if self.s.provider == "litellm":
            import litellm
            kwargs: dict[str, Any] = dict(
                model=self._routed_model(),
                messages=self._maybe_cache(messages),
                max_tokens=self.s.max_tokens,
                temperature=self.s.temperature,
            )
            if self.s.base_url:
                kwargs["base_url"] = self.s.base_url
            if self.s.api_key:
                kwargs["api_key"] = self.s.api_key
            if tools:
                kwargs["tools"] = tools
            raw = litellm.completion(**kwargs)
            return self._parse_litellm(raw)

        assert self._openai_client is not None
        kwargs = dict(
            model=self.s.model, messages=messages,
            max_tokens=self.s.max_tokens, temperature=self.s.temperature,
        )
        if tools:
            kwargs["tools"] = tools
        raw = self._openai_client.chat.completions.create(**kwargs)
        return self._parse_litellm(raw)  # same wire shape

    # ------------------------------------------------------------------
    def _routed_model(self) -> str:
        """Decide the litellm model string.

        A custom base_url means an OpenAI-compatible gateway: bare names
        ("my-model") need the `openai/` prefix so litellm forwards them;
        already-prefixed vendor names ("anthropic/...") pass through.
        Without a base_url the model string is used verbatim and litellm
        routes by prefix to the vendor API.
        """
        m = self.s.model
        if self.s.base_url and "/" not in m:
            return f"openai/{m}"
        return m

    # ------------------------------------------------------------------
    def _maybe_cache(self, messages: list[dict]) -> list[dict]:
        """Anthropic prompt caching: convert the system prompt into a
        content block with an ephemeral cache breakpoint — it is the bulk
        of every call's prefix (~1k lines + doctrine), so caching it cuts
        per-turn input cost massively on long hunts. OpenAI, DeepSeek and
        Moonshot cache server-side automatically; other providers either
        ignore the block format or never see it (litellm translates).
        """
        if not getattr(self.s, "prompt_cache", True):
            return messages
        if "claude" not in self.s.model.lower():
            return messages
        out: list[dict] = []
        for msg in messages:
            if msg.get("role") == "system" and isinstance(msg.get("content"), str):
                out.append({**msg, "content": [
                    {"type": "text", "text": msg["content"],
                     "cache_control": {"type": "ephemeral"}}]})
            else:
                out.append(msg)
        return out

    # ------------------------------------------------------------------
    def _parse_litellm(self, raw: Any) -> LLMResponse:
        # a 403 WALLET_BUSY / rate body can arrive as an SDK object WITHOUT
        # choices — parsing it silently yields a blank turn (the llm_lost
        # signature). Treat it as a retryable transport error instead.
        if not getattr(raw, "choices", None):
            body = getattr(raw, "model_extra", None) or getattr(raw, "dict",
                                                                lambda: {})()
            raise ValueError(f"LLM response has no choices "
                             f"(rate/WALLET_BUSY body): {str(body)[:200]}")
        choice = raw.choices[0]
        msg = choice.message
        calls: list[ToolCall] = []
        for tc in getattr(msg, "tool_calls", None) or []:
            fn = tc.function
            try:
                args = json.loads(fn.arguments or "{}")
            except json.JSONDecodeError:
                args = {"_raw": fn.arguments}
            calls.append(ToolCall(id=tc.id, name=fn.name, arguments=args))
        usage = getattr(raw, "usage", None)
        usage_dict = {
            "prompt_tokens": getattr(usage, "prompt_tokens", 0) or 0,
            "completion_tokens": getattr(usage, "completion_tokens", 0) or 0,
        }
        self.total_prompt_tokens += usage_dict["prompt_tokens"]
        self.total_completion_tokens += usage_dict["completion_tokens"]
        return LLMResponse(
            text=getattr(msg, "content", None) or "",
            tool_calls=calls,
            finish_reason=choice.finish_reason or "",
            usage=usage_dict,
        )
