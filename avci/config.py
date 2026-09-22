"""AVCI configuration: env-first, YAML-optional, fail-loud."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path

DEFAULT_STATE_DIR = Path(os.environ.get("AVCI_STATE_DIR", "runs"))
DEFAULT_MCP_CONFIG = Path(os.environ.get("AVCI_MCP_CONFIG", "configs/mcp_servers.json"))


@dataclass
class LLMSettings:
    """Any LLM with tool calling, via LiteLLM routing or a direct
    OpenAI-compatible endpoint.

    provider=litellm (default): the model string decides the vendor
    (claude-*, gpt-*, deepseek/*, moonshot/*, gemini/*, ollama/*, ...);
    keys come from the vendor env vars (ANTHROPIC_API_KEY, OPENAI_API_KEY,
    DEEPSEEK_API_KEY, MOONSHOT_API_KEY, ...) unless api_key is set.
    Set base_url to point at any OpenAI-compatible gateway (LiteLLM proxy,
    OpenRouter, Ollama, vLLM, a local relay) — bare model names are then
    sent through that gateway.

    provider=openai: talk straight to base_url with the OpenAI SDK.
    """

    base_url: str = os.environ.get("AVCI_LLM_BASE_URL", "")
    api_key: str = os.environ.get("AVCI_LLM_API_KEY", "")
    model: str = os.environ.get("AVCI_LLM_MODEL", "claude-sonnet-4-5")
    provider: str = os.environ.get("AVCI_LLM_PROVIDER", "litellm")  # litellm | openai
    max_tokens: int = int(os.environ.get("AVCI_LLM_MAX_TOKENS", "8192"))
    temperature: float = float(os.environ.get("AVCI_LLM_TEMPERATURE", "0.2"))
    request_timeout: float = float(os.environ.get("AVCI_LLM_TIMEOUT", "180"))
    # Anthropic prompt caching (system prompt is the bulk of every call's
    # prefix). OpenAI/DeepSeek/Moonshot cache server-side automatically.
    prompt_cache: bool = os.environ.get("AVCI_LLM_CACHE", "1") == "1"
    # provider outages outlive the client's ~2min of transport retries:
    # grant the hunt a few long-grace rounds before declaring llm_lost
    # (autopsy: llm_lost was 18% of all failed XBOW attempts)
    grace_retries: int = int(os.environ.get("AVCI_LLM_GRACE", "2"))
    grace_wait: float = float(os.environ.get("AVCI_LLM_GRACE_WAIT", "90"))


@dataclass
class AgentSettings:
    max_iterations: int = int(os.environ.get("AVCI_MAX_ITERATIONS", "120"))
    tool_call_timeout: float = float(os.environ.get("AVCI_TOOL_TIMEOUT", "600"))
    allow_private_targets: bool = os.environ.get("AVCI_ALLOW_PRIVATE", "0") == "1"
    # scan tool output for prompt-injection before it reaches the LLM
    injection_guard: bool = os.environ.get("AVCI_INJECTION_GUARD", "1") == "1"


@dataclass
class ReconSettings:
    crawl_depth: int = 3
    crawl_max_pages: int = 250
    param_wordlist_size: int = 120
    top_ports: tuple[int, ...] = (
        80, 443, 8000, 8080, 8443, 3000, 5000, 5173, 9000,
        22, 21, 25, 3306, 5432, 6379, 27017, 9200, 15672,
    )
    concurrency: int = 16
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    )


@dataclass
class Settings:
    llm: LLMSettings = field(default_factory=LLMSettings)
    agent: AgentSettings = field(default_factory=AgentSettings)
    recon: ReconSettings = field(default_factory=ReconSettings)
    scope_rules: list[str] = field(default_factory=list)
    state_dir: Path = DEFAULT_STATE_DIR
    mcp_config_path: Path = DEFAULT_MCP_CONFIG

    # ------------------------------------------------------------------
    @classmethod
    def load(cls, scope: list[str] | None = None, overrides: dict | None = None) -> "Settings":
        s = cls()
        s.scope_rules = list(scope or [])
        if overrides:
            for key, val in overrides.items():
                _deep_set(s, key, val)
        return s

    def dump(self) -> str:
        d = asdict(self)
        d["state_dir"] = str(self.state_dir)
        d["mcp_config_path"] = str(self.mcp_config_path)
        return json.dumps(d, indent=2, default=str)


def _deep_set(obj: object, dotted: str, value: object) -> None:
    node = obj
    parts = dotted.split(".")
    for p in parts[:-1]:
        node = getattr(node, p)
    setattr(node, parts[-1], value)
