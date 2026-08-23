"""AI-generated triage text for a scan finding — provider-agnostic.

AI_PROVIDER picks which backend answers analyze(): "gemini" (default),
"openai", "anthropic", or "openai_compatible" — any OpenAI-wire-compatible
endpoint (DeepSeek, Qwen, Moonshot/Kimi, most other providers, or a
self-hosted server like Ollama/LM Studio/vLLM/llama.cpp) via AI_BASE_URL.
config.get_settings() already guarantees the selected provider's required
vars are set (or the process fails to boot) — see
config._require_ai_provider_configured.

Each provider function builds its own client per call, matching the
per-call-client pattern already used in registry.py/cloudflare.py — this
runs once per container scan, not in a hot loop, so there's nothing to
cache.
"""

from __future__ import annotations

import anthropic
from google import genai
from google.genai import types
from openai import OpenAI

from .config import Settings, get_settings

SYSTEM_PROMPT = (
    "You are a professional security consultant for a Raspberry Pi 4 CasaOS "
    "environment. Keep your answers as short as possible."
)


def analyze(image: str, summary: str) -> str:
    settings = get_settings()
    prompt = f"Analyze these vulnerabilities for {image}:\n{summary}\n\nSummarize the risk and suggest fixes."
    if settings.ai_provider == "gemini":
        return _analyze_gemini(settings, prompt)
    if settings.ai_provider == "openai":
        return _analyze_openai(settings.openai_api_key, settings.openai_model, prompt)
    if settings.ai_provider == "anthropic":
        return _analyze_anthropic(settings, prompt)
    if settings.ai_provider == "openai_compatible":
        # Most self-hosted servers (Ollama, LM Studio, vLLM, llama.cpp) don't
        # check the key at all — AI_API_KEY is optional (see config.py), so
        # this needs a non-empty placeholder purely to satisfy the client.
        return _analyze_openai(
            settings.ai_api_key or "not-needed", settings.ai_model, prompt, base_url=settings.ai_base_url
        )
    raise RuntimeError(f"Unknown AI_PROVIDER: {settings.ai_provider!r}")  # pragma: no cover — get_settings guards this


def _analyze_gemini(settings: Settings, prompt: str) -> str:
    client = genai.Client(api_key=settings.gemini_api_key)
    response = client.models.generate_content(
        model=settings.gemini_model,
        contents=prompt,
        config=types.GenerateContentConfig(system_instruction=SYSTEM_PROMPT),
    )
    return response.text


def _analyze_openai(api_key: str, model: str, prompt: str, base_url: str | None = None) -> str:
    client = OpenAI(api_key=api_key, base_url=base_url or None)
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
    )
    return response.choices[0].message.content or ""


def _analyze_anthropic(settings: Settings, prompt: str) -> str:
    client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
    response = client.messages.create(
        model=settings.anthropic_model,
        max_tokens=4096,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )
    return next((block.text for block in response.content if block.type == "text"), "")
