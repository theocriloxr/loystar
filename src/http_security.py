"""ASGI middleware for MCP transport and browser-facing OAuth security."""
from __future__ import annotations

from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from src.config import settings


class MCPContentTypeMiddleware:
    """Require JSON for the Streamable HTTP request body."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] == "http"
            and scope.get("path") == "/mcp"
            and scope.get("method") == "POST"
        ):
            content_type = Headers(scope=scope).get("content-type", "")
            media_type = content_type.split(";", 1)[0].strip().lower()
            if media_type != "application/json":
                response = JSONResponse(
                    {"detail": "Content-Type must be application/json."},
                    status_code=415,
                )
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


class RequestBodyLimitMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        content_length = headers.get("content-length")
        try:
            if content_length and int(content_length) > self.max_bytes:
                response = JSONResponse({"detail": "Request body too large."}, status_code=413)
                await response(scope, receive, send)
                return
        except ValueError:
            response = JSONResponse({"detail": "Invalid Content-Length."}, status_code=400)
            await response(scope, receive, send)
            return

        body_parts: list[bytes] = []
        total = 0
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] != "http.request":
                continue
            body = message.get("body", b"")
            total += len(body)
            if total > self.max_bytes:
                response = JSONResponse({"detail": "Request body too large."}, status_code=413)
                await response(scope, receive, send)
                return
            body_parts.append(body)
            more_body = message.get("more_body", False)

        complete_body = b"".join(body_parts)
        delivered = False

        async def replay_receive() -> Message:
            nonlocal delivered
            if delivered:
                return {"type": "http.request", "body": b"", "more_body": False}
            delivered = True
            return {"type": "http.request", "body": complete_body, "more_body": False}

        await self.app(scope, replay_receive, send)


class OriginValidationMiddleware:
    """Validate browser Origin on MCP requests to prevent DNS rebinding."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        origin = Headers(scope=scope).get("origin")
        if path.startswith("/mcp") and origin:
            normalized = origin.rstrip("/")
            if normalized not in settings.allowed_origins:
                response = JSONResponse({"detail": "Origin is not allowed."}, status_code=403)
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


class ProductionHTTPSMiddleware:
    """Reject plaintext external requests in production without redirecting secrets."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not settings.is_production:
            await self.app(scope, receive, send)
            return
            
        path = scope.get("path", "")
        if path == "/health" or path == "/live":
            await self.app(scope, receive, send)
            return
            
        headers = Headers(scope=scope)
        scheme = scope.get("scheme", "http")
        if settings.trust_proxy_headers:
            scheme = headers.get("x-forwarded-proto", scheme).split(",", 1)[0].strip()
        if scheme != "https":
            response = JSONResponse({"detail": "HTTPS is required."}, status_code=400)
            await response(scope, receive, send)
            return
            
        scope["scheme"] = "https"
        await self.app(scope, receive, send)


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def security_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                additions: dict[bytes, bytes] = {
                    b"x-content-type-options": b"nosniff",
                    b"x-frame-options": b"DENY",
                    b"referrer-policy": b"no-referrer",
                    b"permissions-policy": b"camera=(), microphone=(), geolocation=()",
                    b"content-security-policy": (
                        b"default-src 'none'; style-src 'unsafe-inline'; "
                        b"form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
                    ),
                }
                path = scope.get("path", "")
                if path.startswith("/oauth/") or path.startswith("/admin/"):
                    additions[b"cache-control"] = b"no-store"
                    additions[b"pragma"] = b"no-cache"
                if settings.is_production:
                    additions[b"strict-transport-security"] = (
                        b"max-age=31536000; includeSubDomains"
                    )
                existing = {key.lower() for key, _ in headers}
                headers.extend(
                    (key, value)
                    for key, value in additions.items()
                    if key not in existing
                )
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, security_send)
