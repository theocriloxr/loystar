"""AI Provider registry and factory for the Loystar MCP Server.

This module provides the same multi-AI-provider abstraction as the
Loystar Import Helper, adapted for the MCP server's embedding needs.

The active provider is selected via the `AI_PROVIDER` environment variable
or defaults to the first available provider.
"""

import logging
from typing import Optional

from src.config import settings

logger = logging.getLogger(__name__)

# ── Provider registry ─────────────────────────────────────────────────────────
_registry: dict[str, "AIProvider"] = {}  # noqa: F821


def _build_registry() -> dict[str, "AIProvider"]:  # noqa: F821
    """Lazily build and cache the provider registry."""
    if _registry:
        return _registry

    from src.ai_providers.gemini import GeminiProvider
    from src.ai_providers.openai import OpenAIProvider
    from src.ai_providers.anthropic import AnthropicProvider

    providers: list[AIProvider] = [  # noqa: F821
        GeminiProvider(api_key=settings.gemini_api_key),
        OpenAIProvider(
            api_key=settings.openai_api_key,
            embedding_model=settings.openai_embedding_model,
            chat_model=settings.openai_chat_model,
        ),
        AnthropicProvider(
            api_key=settings.anthropic_api_key,
            model=settings.anthropic_chat_model,
        ),
    ]

    for p in providers:
        _registry[p.name] = p

    logger.info(
        "AI provider registry: %s",
        {k: v.is_available() for k, v in _registry.items()},
    )
    return _registry


def get_provider(name: Optional[str] = None) -> "AIProvider":  # noqa: F821
    """Return the active AI provider.

    Args:
        name: Provider identifier, e.g. ``"gemini"``, ``"openai"``, ``"anthropic"``.
              When *None* (default) the value of the ``AI_PROVIDER`` env var or
              the first available provider is returned.

    Raises:
        RuntimeError: If no providers are registered or *name* is unknown.
    """
    registry = _build_registry()
    if not registry:
        raise RuntimeError("No AI providers registered — check your configuration.")

    key = (name or settings.ai_provider or "").strip().lower()
    if key:
        provider = registry.get(key)
        if provider is None:
            available = list(registry.keys())
            raise RuntimeError(
                f"Unknown AI provider {key!r}. Available: {available}"
            )
        return provider

    # Fallback: return the first *available* provider or the first one registered.
    for p in registry.values():
        if p.is_available():
            return p
    return next(iter(registry.values()))


def list_providers() -> list[dict]:
    """Return metadata about every registered provider (for the frontend)."""
    registry = _build_registry()
    return [
        {
            "name": p.name,
            "model": p.default_model,
            "available": p.is_available(),
        }
        for p in registry.values()
    ]


def get_active_provider_info() -> dict:
    """Return metadata about the currently active provider."""
    p = get_provider()
    return {
        "name": p.name,
        "model": p.default_model,
        "available": p.is_available(),
    }
