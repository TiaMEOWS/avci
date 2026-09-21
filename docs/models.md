# Model setup — AVCI runs on any LLM with solid tool calling

AVCI talks to models through [LiteLLM](https://github.com/BerriAI/litellm),
so the model string picks the vendor and keys come from the usual env vars.
The agent loop needs **function/tool calling** — pick a model that is good
at it. Long hunts resend context; prompt-caching-friendly vendors keep
costs down.

| Provider | `AVCI_LLM_MODEL` | API key env var | Notes |
|---|---|---|---|
| Anthropic | `claude-sonnet-4-5` (default) | `ANTHROPIC_API_KEY` | best tool-use discipline in testing |
| Anthropic | `claude-opus-4-1` | `ANTHROPIC_API_KEY` | deepest reasoning, priciest |
| OpenAI | `gpt-5` / `gpt-5-mini` | `OPENAI_API_KEY` | strong all-round |
| DeepSeek | `deepseek/deepseek-chat` | `DEEPSEEK_API_KEY` | very cheap, good injection classes |
| Moonshot Kimi | `moonshot/kimi-k2-0711-preview` | `MOONSHOT_API_KEY` | large context, good for long hunts |
| Google | `gemini/gemini-2.5-pro` | `GEMINI_API_KEY` | large context |
| Zhipu GLM | `glm-4.6` | `ZHIPUAI_API_KEY` | — |
| OpenRouter | `openrouter/<vendor>/<model>` | `OPENROUTER_API_KEY` | one key for everything |
| Ollama (local) | `ollama/qwen3:32b` | none | needs a model with real tool calling |

## Quick setup

```powershell
# example: Claude
$env:ANTHROPIC_API_KEY = "sk-ant-..."
$env:AVCI_LLM_MODEL    = "claude-sonnet-4-5"   # optional, this is the default

# example: DeepSeek
$env:DEEPSEEK_API_KEY  = "sk-..."
$env:AVCI_LLM_MODEL    = "deepseek/deepseek-chat"

avci doctor    # verifies the model round-trips
```

## Gateways & local proxies

Point `AVCI_LLM_BASE_URL` at any OpenAI-compatible gateway — LiteLLM proxy,
OpenRouter, vLLM, a company relay. Bare model names are then forwarded
through the gateway (`openai/<model>` routing):

```powershell
$env:AVCI_LLM_BASE_URL = "http://127.0.0.1:4011/v1"
$env:AVCI_LLM_API_KEY  = "..."
$env:AVCI_LLM_MODEL    = "my-gateway-model"
```

`AVCI_LLM_PROVIDER=openai` skips LiteLLM entirely and talks to `base_url`
with the OpenAI SDK.

## Tuning

| Env var | Default | Meaning |
|---|---|---|
| `AVCI_LLM_MAX_TOKENS` | `8192` | completion cap per call |
| `AVCI_LLM_TEMPERATURE` | `0.2` | low — the loop wants precision |
| `AVCI_LLM_TIMEOUT` | `180` | per-request seconds |
| `AVCI_MAX_ITERATIONS` | `120` | hunt budget |

Token/USD accounting lands in `runs/<id>/cost.jsonl` and the run summary.
