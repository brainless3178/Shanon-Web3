# LLM Strategist

AI-enhanced vulnerability analysis using large language models. Generates exploit
strategies, infers system invariants, and enhances findings with detailed security insights.

## Configuration

The LLM Strategist requires an API key to function. Supported providers:

| Provider | Key Prefix | API Endpoint |
|----------|------------|-------------|
| OpenRouter | `sk-or-` | `openrouter.ai/api/v1/chat/completions` |
| OpenAI | `sk-proj-` or `sk-` | `api.openai.com/v1/chat/completions` |
| NVIDIA NIM | `nvapi-` | `integrate.api.nvidia.com/v1/chat/completions` |

### Setup

1. Copy `.env.example` to `.env` in the project root:
   ```bash
   cp .env.example .env
   ```

2. Set your API key and preferred model:
   ```env
   OPENROUTER_API_KEY=sk-or-your-key-here
   LLM_MODEL=anthropic/claude-3.5-sonnet
   ```

3. The strategist is instantiated with:
   ```rust
   use llm_strategist::LlmStrategist;

   let strategist = LlmStrategist::new(
       std::env::var("OPENROUTER_API_KEY").unwrap(),
       std::env::var("LLM_MODEL").unwrap_or("anthropic/claude-3.5-sonnet".into()),
   );
   ```

## Features

- **Exploit Strategy Generation** — Produces concrete attack vectors with payloads
- **System Invariant Inference** — Identifies critical logical invariants from program code
- **Finding Enhancement** — Enriches vulnerability findings with PoC code, fix suggestions,
  economic impact assessment, and references to real-world exploits
- **Multi-provider Support** — Works with OpenRouter, OpenAI, and NVIDIA NIM APIs
- **Kimi K2.5 / Nemotron Support** — Special configuration for reasoning models

## Without API Keys

The crate compiles and its data structures work without API keys. Only the async
methods that call external LLM APIs (`generate_exploit_strategy`, `enhance_finding`,
`infer_system_invariants`) require a valid key at runtime.
