"""Abstract base class for AI providers in the Loystar MCP Server.

Each provider implements the `generate_embedding(text)` method which takes
a string and returns a vector of floats. Providers are registered in the
PROVIDER_REGISTRY and selected via the `AI_PROVIDER` environment variable.
"""

import json
import logging
import re
from abc import ABC, abstractmethod
from typing import Any, Optional

logger = logging.getLogger(__name__)


class AIProvider(ABC):
    """Abstract AI provider for embedding generation.

    Subclasses must implement:
        generate_embedding(text) -> list[float]
        name -> str
        default_model -> str
        is_available() -> bool
    """

    @abstractmethod
    def generate_embedding(self, text: str) -> list[float]:
        """Generate an embedding vector for the given text.

        Args:
            text: The input text to embed.

        Returns:
            A list of floats representing the embedding vector.

        Raises:
            RuntimeError: If the model call fails or returns empty content.
        """
        ...

    @abstractmethod
    def generate(self, prompt: str) -> str:
        """Send a prompt to the AI model and return the text response.

        Raises:
            RuntimeError: If the model call fails or returns empty content.
        """
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable provider identifier, e.g. 'openai', 'gemini'."""
        ...

    @property
    @abstractmethod
    def default_model(self) -> str:
        """Default model identifier, e.g. 'text-embedding-3-small'."""
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Return True when the provider has valid credentials configured."""
        ...

    def __repr__(self) -> str:
        cls = self.__class__.__name__
        return f"<{cls} name={self.name!r} model={self.default_model!r} available={self.is_available()}>"
