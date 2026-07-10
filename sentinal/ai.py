from __future__ import annotations

from google import genai
from google.genai import types

from .config import get_settings

SYSTEM_PROMPT = (
    "You are a professional security consultant for a Raspberry Pi 4 CasaOS "
    "environment. Keep your answers as short as possible."
)


def analyze(image: str, summary: str) -> str:
    settings = get_settings()
    client = genai.Client(api_key=settings.gemini_api_key)
    prompt = f"Analyze these vulnerabilities for {image}:\n{summary}\n\nSummarize the risk and suggest fixes."
    response = client.models.generate_content(
        model=settings.gemini_model,
        contents=prompt,
        config=types.GenerateContentConfig(system_instruction=SYSTEM_PROMPT),
    )
    return response.text
