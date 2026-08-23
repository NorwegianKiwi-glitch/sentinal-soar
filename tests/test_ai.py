from __future__ import annotations

from unittest import mock

from sentinal import ai


def _settings(**overrides):
    defaults = dict(
        ai_provider="gemini",
        gemini_api_key="g-key",
        gemini_model="gemini-2.5-flash",
        openai_api_key="",
        openai_model="",
        anthropic_api_key="",
        anthropic_model="claude-opus-5",
        ai_base_url="",
        ai_api_key="",
        ai_model="",
    )
    defaults.update(overrides)
    return type("S", (), defaults)()


def test_analyze_dispatches_to_gemini_by_default(monkeypatch):
    monkeypatch.setattr(ai, "get_settings", lambda: _settings())
    fake_response = mock.Mock(text="gemini says hi")
    fake_client = mock.Mock()
    fake_client.models.generate_content.return_value = fake_response
    monkeypatch.setattr(ai.genai, "Client", mock.Mock(return_value=fake_client))

    result = ai.analyze("nginx:latest", "CVE-1")

    assert result == "gemini says hi"
    ai.genai.Client.assert_called_once_with(api_key="g-key")
    kwargs = fake_client.models.generate_content.call_args.kwargs
    assert kwargs["model"] == "gemini-2.5-flash"
    assert "nginx:latest" in kwargs["contents"]


def test_analyze_dispatches_to_openai(monkeypatch):
    monkeypatch.setattr(
        ai, "get_settings", lambda: _settings(ai_provider="openai", openai_api_key="sk-x", openai_model="gpt-x")
    )
    fake_response = mock.Mock()
    fake_response.choices = [mock.Mock(message=mock.Mock(content="openai says hi"))]
    fake_client = mock.Mock()
    fake_client.chat.completions.create.return_value = fake_response
    fake_openai_cls = mock.Mock(return_value=fake_client)
    monkeypatch.setattr(ai, "OpenAI", fake_openai_cls)

    result = ai.analyze("nginx:latest", "CVE-1")

    assert result == "openai says hi"
    fake_openai_cls.assert_called_once_with(api_key="sk-x", base_url=None)
    assert fake_client.chat.completions.create.call_args.kwargs["model"] == "gpt-x"


def test_analyze_dispatches_to_anthropic(monkeypatch):
    monkeypatch.setattr(ai, "get_settings", lambda: _settings(ai_provider="anthropic", anthropic_api_key="sk-ant-x"))
    fake_block = mock.Mock(type="text", text="claude says hi")
    fake_response = mock.Mock(content=[fake_block])
    fake_client = mock.Mock()
    fake_client.messages.create.return_value = fake_response
    fake_anthropic_cls = mock.Mock(return_value=fake_client)
    monkeypatch.setattr(ai.anthropic, "Anthropic", fake_anthropic_cls)

    result = ai.analyze("nginx:latest", "CVE-1")

    assert result == "claude says hi"
    fake_anthropic_cls.assert_called_once_with(api_key="sk-ant-x")
    assert fake_client.messages.create.call_args.kwargs["model"] == "claude-opus-5"


def test_analyze_dispatches_to_openai_compatible_with_base_url(monkeypatch):
    monkeypatch.setattr(
        ai,
        "get_settings",
        lambda: _settings(ai_provider="openai_compatible", ai_base_url="http://ollama:11434/v1", ai_model="llama3"),
    )
    fake_response = mock.Mock()
    fake_response.choices = [mock.Mock(message=mock.Mock(content="local model says hi"))]
    fake_client = mock.Mock()
    fake_client.chat.completions.create.return_value = fake_response
    fake_openai_cls = mock.Mock(return_value=fake_client)
    monkeypatch.setattr(ai, "OpenAI", fake_openai_cls)

    result = ai.analyze("nginx:latest", "CVE-1")

    assert result == "local model says hi"
    # No API key configured — a self-hosted server typically doesn't check it,
    # but the client still needs a non-empty string, hence the placeholder.
    fake_openai_cls.assert_called_once_with(api_key="not-needed", base_url="http://ollama:11434/v1")
    assert fake_client.chat.completions.create.call_args.kwargs["model"] == "llama3"
