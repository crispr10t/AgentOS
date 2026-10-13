"""Unit and Integration Tests for AgentOS Cloud LLM Client (Groq, Gemini, OpenAI)."""

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
    assert config.provider == LLMProvider.GROQ
    assert config.groq_model == "llama-3.3-70b-versatile"
    assert config.groq_base_url == "https://api.groq.com/openai/v1"
    assert config.gemini_model == "gemini-3.8-flash"
    assert config.auto_fallback is True
    assert config.timeout_sec > 0


def test_llm_config_from_env_groq(monkeypatch):
    """Verifies parsing Groq configuration from environment variables."""
    monkeypatch.setenv("LLM_PROVIDER", "groq")
    monkeypatch.setenv("GROQ_API_KEY", "gsk_testkey123")
    monkeypatch.setenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    monkeypatch.setenv("LLM_TIMEOUT_SECONDS", "25")

    config = LLMConfig.from_env()
    assert config.provider == LLMProvider.GROQ
    assert config.groq_api_key == "gsk_testkey123"
    assert config.groq_model == "llama-3.3-70b-versatile"
    assert config.timeout_sec == 25.0


def test_llm_config_from_env_openai(monkeypatch):
    """Verifies parsing OpenAI configuration from environment variables."""
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


def test_groq_provider_success():
    """Verifies calling Groq via mocked OpenAI client."""
    config = LLMConfig(
        provider=LLMProvider.GROQ,
        groq_api_key="gsk_mock_key",
        groq_model="llama-3.3-70b-versatile",
    )
    client = LLMClient(config=config)

    mock_chat = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.content = '{"plan_description": "Groq plan", "steps": []}'
    mock_chat.choices = [mock_choice]
    mock_chat.usage = {"total_tokens": 100}

    mock_openai_instance = MagicMock()
    mock_openai_instance.chat.completions.create.return_value = mock_chat

    with patch("openai.OpenAI", return_value=mock_openai_instance) as mock_openai_cls:
        resp = client.generate(prompt="Compile Java code", format_json=True)
        assert resp.provider == "groq"
        assert resp.model == "llama-3.3-70b-versatile"
        assert "Groq plan" in resp.content
        assert resp.fallback_occurred is False

        mock_openai_cls.assert_called_once_with(
            api_key="gsk_mock_key",
            base_url="https://api.groq.com/openai/v1",
            timeout=config.timeout_sec,
        )


def test_groq_fallback_to_gemini_on_error():
    """Verifies automatic fallback to Gemini when Groq encounters an error."""
    config = LLMConfig(
        provider=LLMProvider.GROQ,
        groq_api_key="gsk_failing_key",
        gemini_api_key="gemini_test_key",
        auto_fallback=True,
    )
    client = LLMClient(config=config)

    with patch.object(client, "_call_groq", side_effect=RuntimeError("Groq rate limited")), \
         patch.object(client, "_call_gemini") as mock_gemini:
        mock_gemini.return_value = LLMResponse(
            content='{"plan_description": "Fallback Gemini plan", "steps": []}',
            provider="gemini",
            model="gemini-3.8-flash",
            duration_sec=0.5,
        )

        resp = client.generate(prompt="Create test plan")
        assert resp.fallback_occurred is True
        assert resp.fallback_from == "groq"
        assert resp.provider == "gemini"
        assert "Fallback Gemini plan" in resp.content
        mock_gemini.assert_called_once()


def test_gemini_fallback_to_groq_on_error():
    """Verifies automatic fallback to Groq when Gemini encounters an error."""
    config = LLMConfig(
        provider=LLMProvider.GEMINI,
        gemini_api_key="gemini_failing_key",
        groq_api_key="gsk_test_key",
        auto_fallback=True,
    )
    client = LLMClient(config=config)

    with patch.object(client, "_call_gemini", side_effect=RuntimeError("Gemini quota exceeded")), \
         patch.object(client, "_call_groq") as mock_groq:
        mock_groq.return_value = LLMResponse(
            content='{"plan_description": "Fallback Groq plan", "steps": []}',
            provider="groq",
            model="llama-3.3-70b-versatile",
            duration_sec=0.2,
        )

        resp = client.generate(prompt="Read system info")
        assert resp.fallback_occurred is True
        assert resp.fallback_from == "gemini"
        assert resp.provider == "groq"
        assert "Fallback Groq plan" in resp.content
        mock_groq.assert_called_once()


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


def test_error_raised_when_fallback_disabled():
    """Verifies that an error is raised directly when auto_fallback is disabled."""
    config = LLMConfig(
        provider=LLMProvider.GROQ,
        groq_api_key=None,
        auto_fallback=False,
    )
    client = LLMClient(config=config)

    with pytest.raises(LLMClientError, match="Groq API invocation failed"):
        client.generate(prompt="Should fail immediately")


def test_error_raised_when_no_fallback_configured():
    """Verifies error raised when Groq fails and no Gemini fallback key is available."""
    config = LLMConfig(
        provider=LLMProvider.GROQ,
        groq_api_key="bad-key",
        gemini_api_key=None,
        auto_fallback=True,
    )
    client = LLMClient(config=config)

    with patch.object(client, "_call_groq", side_effect=RuntimeError("Auth error")):
        with pytest.raises(LLMClientError, match="Groq API invocation failed"):
            client.generate(prompt="Should fail without secondary key")


def test_ollama_provider_deprecated():
    """Verifies that selecting legacy Ollama provider raises a clear guidance error."""
    config = LLMConfig(provider=LLMProvider.OLLAMA)
    client = LLMClient(config=config)

    with pytest.raises(LLMClientError, match="Local Ollama provider is disabled"):
        client.generate(prompt="Should raise disabled error")


def test_check_connection():
    """Verifies connection health probing utility for Groq and Gemini."""
    config = LLMConfig(
        provider=LLMProvider.GROQ,
        groq_api_key="gsk_present",
    )
    client = LLMClient(config=config)
    status = client.check_connection()
    assert status["configured_provider"] == "groq"
    assert status["cloud_key_present"] is True

    config_gemini = LLMConfig(
        provider=LLMProvider.GEMINI,
        gemini_api_key=None,
    )
    client_gemini = LLMClient(config=config_gemini)
    status_gemini = client_gemini.check_connection()
    assert status_gemini["configured_provider"] == "gemini"
    assert status_gemini["cloud_key_present"] is False


def test_extract_retry_delay():
    """Verifies parsing of rate limit delay expressions."""
    err_ms = RuntimeError("Rate limit reached. Please try again in 480ms.")
    delay = LLMClient._extract_retry_delay(err_ms)
    assert 0.5 <= delay <= 0.6

    err_s = RuntimeError("Rate limit reached. Please try again in 2.5s.")
    delay_s = LLMClient._extract_retry_delay(err_s)
    assert 2.5 <= delay_s <= 2.7

    err_default = RuntimeError("Rate limit exceeded.")
    assert LLMClient._extract_retry_delay(err_default, default=1.5) == 1.5


def test_groq_transient_rate_limit_retry():
    """Verifies _call_groq retries on transient rate limits before succeeding."""
    config = LLMConfig(
        provider=LLMProvider.GROQ,
        groq_api_key="gsk_test_key",
        groq_model="llama-3.3-70b-versatile",
    )
    client = LLMClient(config=config)

    mock_chat = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.content = '{"plan_description": "Recovered plan", "steps": []}'
    mock_chat.choices = [mock_choice]
    mock_chat.usage = {"total_tokens": 50}

    rate_limit_err = RuntimeError("Error code: 429 - Rate limit reached. Please try again in 50ms.")

    mock_openai_instance = MagicMock()
    mock_openai_instance.chat.completions.create.side_effect = [rate_limit_err, mock_chat]

    with patch("openai.OpenAI", return_value=mock_openai_instance), \
         patch("time.sleep") as mock_sleep:
        resp = client.generate(prompt="Do action")
        assert resp.provider == "groq"
        assert "Recovered plan" in resp.content
        assert mock_openai_instance.chat.completions.create.call_count == 2
        mock_sleep.assert_called_once()

