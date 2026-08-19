"""Gemini (Google) AI provider implementation for the MCP server."""

import logging
from typing import Optional

from src.ai_providers.base import AIProvider

logger = logging.getLogger(__name__)


class GeminiProvider(AIProvider):
    """Provider that uses Google Gemini models for embeddings and text generation."""

    def __init__(self, api_key: Optional[str] = None) -> None:
        self._api_key = api_key
        self._client: Optional["genai.Client"] = None  # type: ignore[name-defined]
        self._init_error: Optional[str] = None
        self._init_client()

    def _init_client(self) -> None:
        if not self._api_key:
            self._init_error = "GEMINI_API_KEY not configured"
            logger.info("GeminiProvider: %s", self._init_error)
            return
        try:
            from google import genai

            self._client = genai.Client(api_key=self._api_key)
            logger.info("GeminiProvider: client initialised successfully")
        except Exception as exc:
            self._init_error = str(exc)
            logger.warning("GeminiProvider: could not initialise client — %s", exc)

    # ── AIProvider interface ──────────────────────────────────────────────────

    @property
    def name(self) -> str:
        return "gemini"

    @property
    def default_model(self) -> str:
        return "gemini-2.0-flash"

    def is_available(self) -> bool:
        return self._client is not None

    def generate_embedding(self, text: str) -> list[float]:
        if self._client is None:
            raise RuntimeError(
                f"GeminiProvider is not available: {self._init_error or 'unknown'}"
            )
        # Gemini uses its text generation model's embedding feature
        response = self._client.models.embed_content(
            model="gemini-embedding-experimental",
            contents=text,
        )
        return response.embedding.values

    def generate(self, prompt: str) -> str:
        if self._client is None:
            raise RuntimeError(
                f"GeminiProvider is not available: {self._init_error or 'unknown'}"
            )
        response = self._client.models.generate_content(
            model=self.default_model,
            contents=prompt,
        )
        if not response or not response.text:
            raise RuntimeError("Gemini returned an empty response")
        return response.text
