"""Unit and Integration Tests for Dual LLM Client."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from agent.llm_client import (
    LLMClient,
    LLMClientError,
    LLMConfig,
    LLMProvider,
    LLMResponse,
)


def test_llm_config_defaults():
    """Verifies default configuration properties."""
    config = LLMConfig()
    assert config.provider == LLMProvider.OLLAMA
    assert "11434" in config.ollama_host
    assert config.ollama_model == "llama3.2:3b"
    assert config.auto_fallback is True
    assert config.timeout_sec > 0


def test_llm_config_from_env(monkeypatch):
    """Verifies parsing configuration from environment variables."""
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-mock-key")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-4o")
    monkeypatch.setenv("LLM_TIMEOUT_SECONDS", "45")

    config = LLMConfig.from_env()
    assert config.provider == LLMProvider.OPENAI
    assert config.openai_api_key == "sk-mock-key"
    assert config.openai_model == "gpt-4o"
    assert config.timeout_sec == 45.0


def test_mock_provider_generation():
    """Verifies deterministic generation using the mock provider."""
    expected_json = json.dumps({"plan_description": "Mock plan", "steps": []})
    client = LLMClient(
        config=LLMConfig(provider=LLMProvider.MOCK),
        mock_handler=lambda prompt, system: expected_json,
    )

    resp = client.generate(prompt="Test prompt", system="System rule")
    assert isinstance(resp, LLMResponse)
    assert resp.content == expected_json
    assert resp.provider == "mock"
    assert resp.duration_sec >= 0.0
    assert resp.fallback_occurred is False


def test_ollama_provider_success():
    """Verifies calling Ollama /api/generate via mocked HTTP response."""
    config = LLMConfig(provider=LLMProvider.OLLAMA)
    client = LLMClient(config=config)

    mock_json = {
        "response": '{"plan_description": "Ollama plan", "steps": []}',
        "total_duration": 1200000000,
        "eval_count": 42,
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_json

    with patch("requests.post", return_value=mock_resp) as mock_post:
        resp = client.generate(prompt="Run test", system="Sys prompt", format_json=True)
        assert resp.provider == "ollama"
        assert "Ollama plan" in resp.content
        assert resp.fallback_occurred is False

        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert "/api/generate" in args[0]
        assert kwargs["json"]["format"] == "json"


def test_gemini_fallback_to_ollama_on_missing_key():
    """Verifies automatic fallback to Ollama when Gemini API key is missing."""
    config = LLMConfig(
        provider=LLMProvider.GEMINI,
        gemini_api_key=None,  # No key provided
        auto_fallback=True,
    )
    client = LLMClient(config=config)

    ollama_mock_json = {
        "response": '{"plan_description": "Fallback to Ollama", "steps": []}',
    }
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = ollama_mock_json

    with patch("requests.post", return_value=mock_resp):
        resp = client.generate(prompt="Compile Main.java")
        assert resp.fallback_occurred is True
        assert resp.fallback_from == "gemini"
        assert resp.provider == "ollama"
        assert "Fallback to Ollama" in resp.content


def test_gemini_sdk_uses_configured_timeout_without_retries():
    """Verifies Gemini requests respect the timeout and don't retry silently."""
    config = LLMConfig(
        provider=LLMProvider.GEMINI,
        gemini_api_key="test-key",
        timeout_sec=12.5,
        auto_fallback=False,
    )
    client = LLMClient(config=config)

    with patch("google.genai.Client") as mock_client_class:
        mock_client_class.return_value.models.generate_content.return_value.text = (
            '{"status": "ok"}'
        )

        response = client.generate(prompt="Test prompt")

    http_options = mock_client_class.call_args.kwargs["http_options"]
    assert http_options.timeout == 12_500
    assert http_options.retry_options.attempts == 1
    assert response.provider == "gemini"


def test_openai_fallback_to_ollama_on_api_error():
    """Verifies automatic fallback to Ollama when OpenAI raises an exception."""
    config = LLMConfig(
        provider=LLMProvider.OPENAI,
        openai_api_key="sk-dummy",
        auto_fallback=True,
    )
    client = LLMClient(config=config)

    ollama_mock_json = {
        "response": '{"plan_description": "Fallback after OpenAI failure", "steps": []}',
    }
    mock_post_resp = MagicMock()
    mock_post_resp.status_code = 200
    mock_post_resp.json.return_value = ollama_mock_json

    with patch("openai.OpenAI", side_effect=RuntimeError("Connection timeout")), \
         patch("requests.post", return_value=mock_post_resp):
        resp = client.generate(prompt="Spawn process")
        assert resp.fallback_occurred is True
        assert resp.fallback_from == "openai"
        assert "fallback_reason" in resp.metadata


def test_openai_compatible_provider_uses_configured_base_url():
    """Verifies OpenAI-compatible providers such as xAI can set their endpoint."""
    config = LLMConfig(
        provider=LLMProvider.OPENAI,
        openai_api_key="test-key",
        openai_model="grok-4.7",
        openai_base_url="https://api.x.ai/v1",
        auto_fallback=False,
    )
    client = LLMClient(config=config)

    with patch("openai.OpenAI") as mock_client_class:
        mock_client_class.return_value.chat.completions.create.return_value.choices = [
            MagicMock(message=MagicMock(content='{"status": "ok"}'))
        ]
        response = client.generate(prompt="Test prompt")

    assert mock_client_class.call_args.kwargs["base_url"] == "https://api.x.ai/v1"
    assert response.provider == "openai"
    assert response.model == "grok-4.7"


def test_error_raised_when_fallback_disabled():
    """Verifies that an error is raised directly when auto_fallback is disabled."""
    config = LLMConfig(
        provider=LLMProvider.GEMINI,
        gemini_api_key=None,
        auto_fallback=False,
    )
    client = LLMClient(config=config)

    with pytest.raises(LLMClientError, match="Gemini API invocation failed"):
        client.generate(prompt="Should fail immediately")


def test_error_raised_when_all_providers_fail():
    """Verifies error raised when primary fails and Ollama fallback is unreachable."""
    config = LLMConfig(
        provider=LLMProvider.GEMINI,
        gemini_api_key=None,
        auto_fallback=True,
    )
    client = LLMClient(config=config)

    with patch("requests.post", side_effect=ConnectionError("Ollama daemon down")):
        with pytest.raises(LLMClientError, match="fallback to Ollama also failed"):
            client.generate(prompt="Should fail everywhere")


def test_check_connection():
    """Verifies connection health probing utility."""
    config = LLMConfig(
        provider=LLMProvider.OLLAMA,
        ollama_host="http://localhost:11434",
    )
    client = LLMClient(config=config)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"models": [{"name": "llama3.2:3b"}]}

    with patch("requests.get", return_value=mock_resp):
        status = client.check_connection()
        assert status["configured_provider"] == "ollama"
        assert status["ollama_available"] is True
        assert "llama3.2:3b" in status["ollama_models"]
