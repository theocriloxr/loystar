"""Railway/Railpack entrypoint for the clean Loystar MCP core.

Railway health checks arrive over its private network with an internal Host
header that should not need to be part of the public OAuth/MCP allowlist. This
wrapper normalizes Host only for non-sensitive health endpoints; every other
request, including OAuth and /mcp, still reaches the app with its original Host
and is enforced by TrustedHostMiddleware.
"""
from __future__ import annotations

from urllib.parse import urlparse

from src.config import settings
from src.main_clean import app as clean_app

_HEALTH_PATHS = {"/health", "/healthz", "/live"}
_PUBLIC_HOST = urlparse(settings.canonical_server_origin or settings.server_base_url).hostname


class RailwayHealthHostAdapter:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http" and scope.get("path") in _HEALTH_PATHS and _PUBLIC_HOST:
            headers = list(scope.get("headers") or [])
            normalized = []
            replaced = False
            for key, value in headers:
                if key.lower() == b"host":
                    normalized.append((key, _PUBLIC_HOST.encode("ascii")))
                    replaced = True
                else:
                    normalized.append((key, value))
            if not replaced:
                normalized.append((b"host", _PUBLIC_HOST.encode("ascii")))
            scope = dict(scope)
            scope["headers"] = normalized
        await self.app(scope, receive, send)


app = RailwayHealthHostAdapter(clean_app)

__all__ = ["app"]
