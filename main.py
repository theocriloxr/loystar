"""Railway/Railpack entrypoint for the clean Loystar MCP core.

Railway health checks arrive over its private network with an internal Host
header that should not need to be part of the public OAuth/MCP allowlist. This
wrapper normalizes Host only for non-sensitive health endpoints; every other
request, including OAuth and /mcp, still reaches the app with its original Host
and is enforced by TrustedHostMiddleware.

The wrapper also exposes a non-secret build identifier in response headers so
production logs and live responses can be tied to the exact Railway/Git commit.
"""
from __future__ import annotations

import os
from urllib.parse import urlparse

from src.config import settings
from src.main_clean import app as clean_app

_HEALTH_PATHS = {"/health", "/healthz", "/live"}
_PUBLIC_HOST = urlparse(settings.canonical_server_origin or settings.server_base_url).hostname
_BUILD_SHA = (
    os.getenv("RAILWAY_GIT_COMMIT_SHA")
    or os.getenv("GIT_COMMIT_SHA")
    or os.getenv("SOURCE_COMMIT")
    or "unknown"
)
_BUILD_BRANCH = os.getenv("RAILWAY_GIT_BRANCH") or os.getenv("GIT_BRANCH") or "unknown"

print(f"LOYSTAR_BUILD_SHA={_BUILD_SHA} LOYSTAR_BUILD_BRANCH={_BUILD_BRANCH}", flush=True)


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

        async def send_with_build(message):
            if message.get("type") == "http.response.start":
                headers = list(message.get("headers") or [])
                if _BUILD_SHA != "unknown":
                    headers.append((b"x-loystar-build", _BUILD_SHA.encode("ascii", "ignore")))
                message = dict(message)
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_build)


app = RailwayHealthHostAdapter(clean_app)

__all__ = ["app"]
