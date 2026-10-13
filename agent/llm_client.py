"""Dual LLM Client with Local Ollama and Cloud Fallback Engine.

Provides a unified interface for the Cognitive Shell to communicate with:
- Local offline models via Ollama (e.g. llama3.2:3b)
- Cloud LLMs via Google Gemini or OpenAI
- Automatic fallback from cloud APIs to local Ollama on network or key failures
- Deterministic mock provider for headless test environments
"""

from __future__ import annotations

from enum import Enum
import os
import time
from typing import Any, Callable, Optional

from dotenv import load_dotenv
from pydantic import BaseModel, Field
import requests

load_dotenv()


class LLMProvider(str, Enum):
    """Supported Large Language Model providers."""

    OLLAMA = "ollama"
    GEMINI = "gemini"
    OPENAI = "openai"
    MOCK = "mock"


class LLMConfig(BaseModel):
    """Configuration options governing LLM access, endpoints, and timeouts."""

    provider: LLMProvider = LLMProvider.OLLAMA
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "llama3.2:3b"
    gemini_api_key: Optional[str] = None
    gemini_model: str = "gemini-2.5-flash"
    openai_api_key: Optional[str] = None
    openai_model: str = "gpt-4o-mini"
    openai_base_url: Optional[str] = None
    timeout_sec: float = 30.0
    temperature: float = 0.1
    auto_fallback: bool = True

    @classmethod
    def from_env(cls) -> LLMConfig:
        """Constructs an LLMConfig from environment variables."""
        provider_raw = os.getenv("LLM_PROVIDER", "ollama").strip().lower()
        try:
            provider = LLMProvider(provider_raw)
        except ValueError:
            provider = LLMProvider.OLLAMA

        return cls(
            provider=provider,
            ollama_host=os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/"),
            ollama_model=os.getenv("OLLAMA_MODEL", "llama3.2:3b"),
            gemini_api_key=os.getenv("GEMINI_API_KEY") or None,
            gemini_model=os.getenv("GEMINI_MODEL", "gemini-2.5-flash"),
            openai_api_key=os.getenv("OPENAI_API_KEY") or None,
            openai_model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            openai_base_url=os.getenv("OPENAI_BASE_URL") or None,
            timeout_sec=float(os.getenv("LLM_TIMEOUT_SECONDS", "30.0")),
            temperature=float(os.getenv("LLM_TEMPERATURE", "0.1")),
            auto_fallback=os.getenv("LLM_AUTO_FALLBACK", "true").lower() in ("1", "true", "yes"),
        )


class LLMResponse(BaseModel):
    """Structured response container encapsulating LLM output and metadata."""

    content: str
    provider: str
    model: str
    duration_sec: float
    fallback_occurred: bool = False
    fallback_from: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class LLMClientError(RuntimeError):
    """Raised when all configured LLM providers fail to generate a response."""

    pass


class LLMClient:
    """Unified client orchestrating local and cloud LLM execution with auto-fallback."""

    def __init__(
        self,
        config: Optional[LLMConfig] = None,
        mock_handler: Optional[Callable[[str, Optional[str]], str]] = None,
    ):
        """Initializes the LLMClient.

        Args:
            config: LLMConfig instance. If None, loaded from environment variables.
            mock_handler: Optional custom callback (prompt, system) -> str for mock testing.
        """
        self.config = config or LLMConfig.from_env()
        self._mock_handler = mock_handler

    def set_mock_handler(
        self, handler: Optional[Callable[[str, Optional[str]], str]]
    ) -> None:
        """Sets or clears a deterministic mock response handler."""
        self._mock_handler = handler

    def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        format_json: bool = True,
    ) -> LLMResponse:
        """Dispatches prompt generation to the active provider with auto-fallback.

        Args:
            prompt: User prompt / command instruction.
            system: Optional system instruction prompt.
            format_json: If True, forces JSON mode if supported by provider.

        Returns:
            LLMResponse containing raw response text and execution metrics.

        Raises:
            LLMClientError: If the primary and fallback providers both fail.
        """
        start_time = time.time()
        provider = self.config.provider

        # 1. Deterministic Mock Provider (for test suites)
        if provider == LLMProvider.MOCK:
            return self._call_mock(prompt, system, start_time)

        # 2. Cloud Providers with Automatic Fallback
        if provider == LLMProvider.GEMINI:
            try:
                return self._call_gemini(prompt, system, format_json, start_time)
            except Exception as exc:
                if self.config.auto_fallback:
                    return self._fallback_to_ollama(
                        prompt, system, format_json, start_time, failed_provider="gemini", error=exc
                    )
                raise LLMClientError(f"Gemini API invocation failed: {exc}") from exc

        if provider == LLMProvider.OPENAI:
            try:
                return self._call_openai(prompt, system, format_json, start_time)
            except Exception as exc:
                if self.config.auto_fallback:
                    return self._fallback_to_ollama(
                        prompt, system, format_json, start_time, failed_provider="openai", error=exc
                    )
                raise LLMClientError(f"OpenAI API invocation failed: {exc}") from exc

        # 3. Local Ollama Provider
        try:
            return self._call_ollama(prompt, system, format_json, start_time)
        except Exception as exc:
            raise LLMClientError(
                f"Local Ollama generation failed at {self.config.ollama_host}: {exc}"
            ) from exc

    def _call_mock(
        self, prompt: str, system: Optional[str], start_time: float
    ) -> LLMResponse:
        """Executes generator via mock handler."""
        duration = time.time() - start_time
        if self._mock_handler is not None:
            content = self._mock_handler(prompt, system)
        else:
            content = (
                '{"plan_description": "Mock mode is active; no actions were '
                'generated or executed.", "steps": []}'
            )
        return LLMResponse(
            content=content,
            provider="mock",
            model="mock-agent",
            duration_sec=duration,
        )

    def _call_ollama(
        self,
        prompt: str,
        system: Optional[str],
        format_json: bool,
        start_time: float,
    ) -> LLMResponse:
        """Invokes local Ollama daemon via REST API (/api/generate)."""
        url = f"{self.config.ollama_host}/api/generate"
        payload: dict[str, Any] = {
            "model": self.config.ollama_model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": self.config.temperature},
        }
        if system:
            payload["system"] = system
        if format_json:
            payload["format"] = "json"

        response = requests.post(url, json=payload, timeout=self.config.timeout_sec)
        response.raise_for_status()
        data = response.json()
        duration = time.time() - start_time

        return LLMResponse(
            content=data.get("response", ""),
            provider="ollama",
            model=self.config.ollama_model,
            duration_sec=duration,
            metadata={
                "total_duration": data.get("total_duration"),
                "eval_count": data.get("eval_count"),
            },
        )

    def _call_gemini(
        self,
        prompt: str,
        system: Optional[str],
        format_json: bool,
        start_time: float,
    ) -> LLMResponse:
        """Invokes Google Gemini Cloud API using google-genai or HTTP."""
        if not self.config.gemini_api_key:
            raise ValueError("GEMINI_API_KEY is not configured.")

        # Attempt SDK invocation via google-genai
        try:
            from google import genai
            from google.genai import types

            client = genai.Client(
                api_key=self.config.gemini_api_key,
                http_options=types.HttpOptions(
                    timeout=int(self.config.timeout_sec * 1000),
                    retry_options=types.HttpRetryOptions(attempts=1),
                ),
            )
            config_args: dict[str, Any] = {
                "temperature": self.config.temperature,
            }
            if system:
                config_args["system_instruction"] = system
            if format_json:
                config_args["response_mime_type"] = "application/json"

            gen_config = types.GenerateContentConfig(**config_args)
            response = client.models.generate_content(
                model=self.config.gemini_model,
                contents=prompt,
                config=gen_config,
            )
            content = response.text or ""
            duration = time.time() - start_time
            return LLMResponse(
                content=content,
                provider="gemini",
                model=self.config.gemini_model,
                duration_sec=duration,
            )
        except ImportError:
            # Fallback to direct HTTP request if SDK is unavailable
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.config.gemini_model}:generateContent?key={self.config.gemini_api_key}"
            contents_payload = [{"parts": [{"text": prompt}]}]
            body: dict[str, Any] = {"contents": contents_payload}
            if system:
                body["systemInstruction"] = {"parts": [{"text": system}]}

            res = requests.post(url, json=body, timeout=self.config.timeout_sec)
            res.raise_for_status()
            res_data = res.json()
            candidates = res_data.get("candidates", [])
            text = ""
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts:
                    text = parts[0].get("text", "")
            duration = time.time() - start_time
            return LLMResponse(
                content=text,
                provider="gemini",
                model=self.config.gemini_model,
                duration_sec=duration,
            )

    def _call_openai(
        self,
        prompt: str,
        system: Optional[str],
        format_json: bool,
        start_time: float,
    ) -> LLMResponse:
        """Invokes OpenAI Cloud API using the official openai library."""
        if not self.config.openai_api_key:
            raise ValueError("OPENAI_API_KEY is not configured.")

        from openai import OpenAI

        client_options: dict[str, Any] = {
            "api_key": self.config.openai_api_key,
            "timeout": self.config.timeout_sec,
        }
        if self.config.openai_base_url:
            client_options["base_url"] = self.config.openai_base_url
        client = OpenAI(**client_options)
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        kwargs: dict[str, Any] = {
            "model": self.config.openai_model,
            "messages": messages,
            "temperature": self.config.temperature,
        }
        if format_json:
            kwargs["response_format"] = {"type": "json_object"}

        chat_completion = client.chat.completions.create(**kwargs)
        content = chat_completion.choices[0].message.content or ""
        duration = time.time() - start_time

        return LLMResponse(
            content=content,
            provider="openai",
            model=self.config.openai_model,
            duration_sec=duration,
            metadata={"usage": getattr(chat_completion, "usage", None)},
        )

    def _fallback_to_ollama(
        self,
        prompt: str,
        system: Optional[str],
        format_json: bool,
        start_time: float,
        failed_provider: str,
        error: Exception,
    ) -> LLMResponse:
        """Gracefully routes execution to local Ollama when cloud provider fails."""
        try:
            resp = self._call_ollama(prompt, system, format_json, start_time)
            resp.fallback_occurred = True
            resp.fallback_from = failed_provider
            resp.metadata["fallback_reason"] = str(error)
            return resp
        except Exception as ollama_err:
            raise LLMClientError(
                f"Primary provider '{failed_provider}' failed ({error}) and "
                f"fallback to Ollama also failed ({ollama_err})."
            ) from error

    def check_connection(self) -> dict[str, Any]:
        """Probes the configured provider endpoints and reports status."""
        status: dict[str, Any] = {
            "configured_provider": self.config.provider.value,
            "ollama_available": False,
            "cloud_key_present": False,
        }

        # Probe Ollama
        try:
            r = requests.get(f"{self.config.ollama_host}/api/tags", timeout=2.0)
            status["ollama_available"] = (r.status_code == 200)
            if status["ollama_available"]:
                models = [m.get("name") for m in r.json().get("models", [])]
                status["ollama_models"] = models
        except Exception:
            status["ollama_available"] = False

        # Probe cloud keys
        if self.config.provider == LLMProvider.GEMINI:
            status["cloud_key_present"] = bool(self.config.gemini_api_key)
        elif self.config.provider == LLMProvider.OPENAI:
            status["cloud_key_present"] = bool(self.config.openai_api_key)

        return status
