"""Anthropic (Claude) AI provider implementation for the MCP server."""

import logging
from typing import Optional

from src.ai_providers.base import AIProvider

logger = logging.getLogger(__name__)


class AnthropicProvider(AIProvider):
    """Provider that uses Anthropic models (Claude) for text generation.

    Note: Anthropic does not currently offer a dedicated embedding API.
    For embedding tasks, use the OpenAI or Gemini provider instead.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
    ) -> None:
        self._api_key = api_key
        self._model = model or "claude-sonnet-4-20250514"
        self._client: Optional["anthropic.Anthropic"] = None  # type: ignore[name-defined]
        self._init_error: Optional[str] = None
        self._init_client()

    def _init_client(self) -> None:
        if not self._api_key:
            self._init_error = "ANTHROPIC_API_KEY not configured"
            logger.info("AnthropicProvider: %s", self._init_error)
            return
        try:
            import anthropic

            self._client = anthropic.Anthropic(api_key=self._api_key)
            logger.info("AnthropicProvider: client initialised successfully")
        except Exception as exc:
            self._init_error = str(exc)
            logger.warning("AnthropicProvider: could not initialise client — %s", exc)

    # ── AIProvider interface ──────────────────────────────────────────────────

    @property
    def name(self) -> str:
        return "anthropic"

    @property
    def default_model(self) -> str:
        return self._model

    def is_available(self) -> bool:
        return self._client is not None

    def generate_embedding(self, text: str) -> list[float]:
        raise RuntimeError(
            "Anthropic does not provide a dedicated embedding API. "
            "Use the OpenAI or Gemini provider for embedding tasks."
        )

    def generate(self, prompt: str) -> str:
        if self._client is None:
            raise RuntimeError(
                f"AnthropicProvider is not available: {self._init_error or 'unknown'}"
            )
        response = self._client.messages.create(
            model=self._model,
            max_tokens=4096,
            system="You are a precise data extraction and analysis engine. Respond only with the requested format.",
            messages=[{"role": "user", "content": prompt}],
        )
        text = response.content[0].text if response.content else ""
        if not text:
            raise RuntimeError("Anthropic returned an empty response")
        return text.strip()
