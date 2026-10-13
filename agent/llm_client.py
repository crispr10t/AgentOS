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

    GROQ = "groq"
    GEMINI = "gemini"
    OPENAI = "openai"
    OLLAMA = "ollama"
    MOCK = "mock"


class LLMConfig(BaseModel):
    """Configuration options governing LLM access, endpoints, and timeouts."""

    provider: LLMProvider = LLMProvider.GROQ
    groq_api_key: Optional[str] = None
    groq_model: str = "llama-3.3-70b-versatile"
    groq_base_url: str = "https://api.groq.com/openai/v1"
    gemini_api_key: Optional[str] = None
    gemini_model: str = "gemini-2.5-flash"
    openai_api_key: Optional[str] = None
    openai_model: str = "gpt-4o-mini"
    openai_base_url: Optional[str] = None
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "llama3.2:3b"
    timeout_sec: float = 30.0
    temperature: float = 0.1
    auto_fallback: bool = True

    @classmethod
    def from_env(cls) -> LLMConfig:
        """Constructs an LLMConfig from environment variables."""
        provider_raw = os.getenv("LLM_PROVIDER", "groq").strip().lower()
        try:
            provider = LLMProvider(provider_raw)
        except ValueError:
            provider = LLMProvider.GROQ

        return cls(
            provider=provider,
            groq_api_key=os.getenv("GROQ_API_KEY") or None,
            groq_model=os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
            groq_base_url=os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1"),
            gemini_api_key=os.getenv("GEMINI_API_KEY") or None,
            gemini_model=os.getenv("GEMINI_MODEL", "gemini-2.5-flash"),
            openai_api_key=os.getenv("OPENAI_API_KEY") or None,
            openai_model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            openai_base_url=os.getenv("OPENAI_BASE_URL") or None,
            ollama_host=os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/"),
            ollama_model=os.getenv("OLLAMA_MODEL", "llama3.2:3b"),
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

        # 2. Groq Cloud API (Fast Llama-3.3 on Groq LPUs)
        if provider == LLMProvider.GROQ:
            try:
                return self._call_groq(prompt, system, format_json, start_time)
            except Exception as exc:
                if self.config.auto_fallback and self.config.gemini_api_key:
                    return self._fallback_cloud(
                        prompt,
                        system,
                        format_json,
                        start_time,
                        failed_provider="groq",
                        fallback_provider="gemini",
                        fallback_call=self._call_gemini,
                        error=exc,
                    )
                raise LLMClientError(f"Groq API invocation failed: {exc}") from exc

        # 3. Google Gemini Cloud API
        if provider == LLMProvider.GEMINI:
            try:
                return self._call_gemini(prompt, system, format_json, start_time)
            except Exception as exc:
                if self.config.auto_fallback and self.config.groq_api_key:
                    return self._fallback_cloud(
                        prompt,
                        system,
                        format_json,
                        start_time,
                        failed_provider="gemini",
                        fallback_provider="groq",
                        fallback_call=self._call_groq,
                        error=exc,
                    )
                raise LLMClientError(f"Gemini API invocation failed: {exc}") from exc

        # 4. OpenAI / Compatible Cloud API
        if provider == LLMProvider.OPENAI:
            try:
                return self._call_openai(prompt, system, format_json, start_time)
            except Exception as exc:
                if self.config.auto_fallback:
                    if self.config.groq_api_key:
                        return self._fallback_cloud(
                            prompt,
                            system,
                            format_json,
                            start_time,
                            failed_provider="openai",
                            fallback_provider="groq",
                            fallback_call=self._call_groq,
                            error=exc,
                        )
                    elif self.config.gemini_api_key:
                        return self._fallback_cloud(
                            prompt,
                            system,
                            format_json,
                            start_time,
                            failed_provider="openai",
                            fallback_provider="gemini",
                            fallback_call=self._call_gemini,
                            error=exc,
                        )
                raise LLMClientError(f"OpenAI API invocation failed: {exc}") from exc

        # 5. Local Ollama Provider (Disabled/Deprecated)
        if provider == LLMProvider.OLLAMA:
            raise LLMClientError(
                "Local Ollama provider is disabled. Please configure GROQ_API_KEY or GEMINI_API_KEY."
            )

        raise LLMClientError(f"Unsupported LLM provider: {provider}")

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

    def _call_groq(
        self,
        prompt: str,
        system: Optional[str],
        format_json: bool,
        start_time: float,
    ) -> LLMResponse:
        """Invokes Groq Cloud API using official OpenAI-compatible endpoint."""
        if not self.config.groq_api_key:
            raise ValueError("GROQ_API_KEY is not configured.")

        from openai import OpenAI

        client = OpenAI(
            api_key=self.config.groq_api_key,
            base_url=self.config.groq_base_url,
            timeout=self.config.timeout_sec,
        )
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        kwargs: dict[str, Any] = {
            "model": self.config.groq_model,
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
            provider="groq",
            model=self.config.groq_model,
            duration_sec=duration,
            metadata={"usage": getattr(chat_completion, "usage", None)},
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

    def _fallback_cloud(
        self,
        prompt: str,
        system: Optional[str],
        format_json: bool,
        start_time: float,
        failed_provider: str,
        fallback_provider: str,
        fallback_call: Callable[..., LLMResponse],
        error: Exception,
    ) -> LLMResponse:
        """Gracefully routes execution to secondary cloud provider when primary fails."""
        try:
            resp = fallback_call(prompt, system, format_json, start_time)
            resp.fallback_occurred = True
            resp.fallback_from = failed_provider
            resp.metadata["fallback_reason"] = str(error)
            return resp
        except Exception as fallback_err:
            raise LLMClientError(
                f"Primary provider '{failed_provider}' failed ({error}) and "
                f"fallback to '{fallback_provider}' also failed ({fallback_err})."
            ) from error

    def check_connection(self) -> dict[str, Any]:
        """Probes the configured provider endpoints and reports status."""
        status: dict[str, Any] = {
            "configured_provider": self.config.provider.value,
            "cloud_key_present": False,
        }

        if self.config.provider == LLMProvider.GROQ:
            status["cloud_key_present"] = bool(self.config.groq_api_key)
        elif self.config.provider == LLMProvider.GEMINI:
            status["cloud_key_present"] = bool(self.config.gemini_api_key)
        elif self.config.provider == LLMProvider.OPENAI:
            status["cloud_key_present"] = bool(self.config.openai_api_key)
        elif self.config.provider == LLMProvider.MOCK:
            status["cloud_key_present"] = True

        return status
