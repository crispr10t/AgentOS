"""Comprehensive edge-case tests for agent/llm_client.py: LLMConfig, LLMProvider, Mocking, and Fallbacks."""

import pytest

from agent.llm_client import (
    LLMClient,
    LLMClientError,
    LLMConfig,
    LLMProvider,
    LLMResponse,
)


# --- 1. LLMConfig & Provider Enum Edge Cases ---

@pytest.mark.parametrize("provider_name, expected_enum", [
    ("groq", LLMProvider.GROQ),
    ("gemini", LLMProvider.GEMINI),
    ("openai", LLMProvider.OPENAI),
    ("mock", LLMProvider.MOCK),
    ("ollama", LLMProvider.OLLAMA),
])
def test_llm_config_from_env_valid_providers(monkeypatch: pytest.MonkeyPatch, provider_name: str, expected_enum: LLMProvider):
    """Verify provider names in LLM_PROVIDER env variable parse to LLMProvider enum."""
    monkeypatch.setenv("LLM_PROVIDER", provider_name)
    config = LLMConfig.from_env()
    assert config.provider == expected_enum


def test_llm_config_from_env_unknown_provider_defaults_to_groq(monkeypatch: pytest.MonkeyPatch):
    """Unknown provider names fall back to default GROQ."""
    monkeypatch.setenv("LLM_PROVIDER", "unknown_provider_xyz")
    config = LLMConfig.from_env()
    assert config.provider == LLMProvider.GROQ


def test_llm_config_custom_initialization():
    """Verify custom parameters in LLMConfig."""
    config = LLMConfig(
        provider=LLMProvider.MOCK,
        timeout_sec=15.0,
        temperature=0.7,
        auto_fallback=False,
    )
    assert config.provider == LLMProvider.MOCK
    assert config.timeout_sec == 15.0
    assert config.temperature == 0.7
    assert config.auto_fallback is False


# --- 2. Deterministic Mock Provider Edge Cases ---

def test_mock_provider_default_response():
    """Verify default mock handler returns empty JSON plan with duration recorded."""
    config = LLMConfig(provider=LLMProvider.MOCK)
    client = LLMClient(config=config)

    res = client.generate("Create a folder and file")
    assert res.provider == "mock"
    assert res.model == "mock-agent"
    assert res.duration_sec >= 0.0
    assert "Mock mode is active" in res.content
    assert '"steps": []' in res.content


def test_mock_provider_custom_handler():
    """Verify custom mock handler returns custom content."""
    config = LLMConfig(provider=LLMProvider.MOCK)
    custom_reply = '{"plan_description": "Custom Mock", "steps": []}'
    client = LLMClient(config=config, mock_handler=lambda p, s: custom_reply)

    res = client.generate("Any prompt")
    assert res.content == custom_reply


def test_mock_provider_dynamically_change_handler():
    """Verify dynamically updating and resetting mock handler."""
    config = LLMConfig(provider=LLMProvider.MOCK)
    client = LLMClient(config=config)

    # Initially default
    res1 = client.generate("test")
    assert "Mock mode is active" in res1.content

    # Set custom handler
    client.set_mock_handler(lambda p, s: "custom-1")
    assert client.generate("test").content == "custom-1"

    # Reset handler
    client.set_mock_handler(None)
    assert "Mock mode is active" in client.generate("test").content


# --- 3. Error Handling and Deprecated Providers ---

def test_ollama_provider_raises_informative_error():
    """Attempting to use disabled Ollama provider raises LLMClientError."""
    config = LLMConfig(provider=LLMProvider.OLLAMA)
    client = LLMClient(config=config)

    with pytest.raises(LLMClientError, match="Local Ollama provider is disabled"):
        client.generate("hello")


def test_groq_missing_api_key_raises():
    """Invoking Groq provider with empty API key raises LLMClientError."""
    config = LLMConfig(provider=LLMProvider.GROQ, groq_api_key="", auto_fallback=False)
    client = LLMClient(config=config)

    with pytest.raises(LLMClientError, match="Groq API invocation failed"):
        client.generate("hello")


def test_gemini_missing_api_key_raises():
    """Invoking Gemini provider with empty API key raises LLMClientError."""
    config = LLMConfig(provider=LLMProvider.GEMINI, gemini_api_key="", auto_fallback=False)
    client = LLMClient(config=config)

    with pytest.raises(LLMClientError, match="Gemini API invocation failed"):
        client.generate("hello")
