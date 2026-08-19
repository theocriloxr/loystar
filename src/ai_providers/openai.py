"""OpenAI (ChatGPT) AI provider implementation for the MCP server."""

import logging
from typing import Optional

from src.ai_providers.base import AIProvider

logger = logging.getLogger(__name__)


class OpenAIProvider(AIProvider):
    """Provider that uses OpenAI models for embeddings and text generation."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        embedding_model: Optional[str] = None,
        chat_model: Optional[str] = None,
        model: Optional[str] = None,
    ) -> None:
        self._api_key = api_key
        self._embedding_model = embedding_model or model or "text-embedding-3-small"
        self._completion_model = chat_model or "gpt-4o-mini"
        self._client: Optional["openai.OpenAI"] = None  # type: ignore[name-defined]
        self._init_error: Optional[str] = None
        self._init_client()

    def _init_client(self) -> None:
        if not self._api_key:
            self._init_error = "OPENAI_API_KEY not configured"
            logger.info("OpenAIProvider: %s", self._init_error)
            return
        try:
            from openai import OpenAI

            self._client = OpenAI(api_key=self._api_key)
            logger.info("OpenAIProvider: client initialised successfully")
        except Exception as exc:
            self._init_error = str(exc)
            logger.warning("OpenAIProvider: could not initialise client — %s", exc)

    # ── AIProvider interface ──────────────────────────────────────────────────

    @property
    def name(self) -> str:
        return "openai"

    @property
    def default_model(self) -> str:
        return self._embedding_model

    def is_available(self) -> bool:
        return self._client is not None

    def generate_embedding(self, text: str) -> list[float]:
        if self._client is None:
            raise RuntimeError(
                f"OpenAIProvider is not available: {self._init_error or 'unknown'}"
            )
        response = self._client.embeddings.create(
            model=self._embedding_model,
            input=text,
        )
        return response.data[0].embedding

    def generate(self, prompt: str) -> str:
        if self._client is None:
            raise RuntimeError(
                f"OpenAIProvider is not available: {self._init_error or 'unknown'}"
            )
        response = self._client.chat.completions.create(
            model=self._completion_model,
            messages=[
                {
                    "role": "system",
                    "content": "You are a precise data extraction and analysis engine. Respond only with the requested format.",
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
        )
        text = response.choices[0].message.content
        if not text:
            raise RuntimeError("OpenAI returned an empty response")
        return text.strip()
