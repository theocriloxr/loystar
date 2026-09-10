"""Claude-hosted connector compatibility without weakening the canonical MCP resource.

Claude.ai has had connector-cache/auth regressions where deleting and re-adding the
same MCP URL does not force a truly fresh OAuth client state.  This module adds a
second, explicit protected resource at ``/mcp-v2``.  It is NOT a redirect:
OAuth codes/tokens for the alias are bound to the alias resource and cannot be
used against canonical ``/mcp`` (and vice versa).
"""
from __future__ import annotations

from types import ModuleType
from typing import Optional

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from starlette.responses import JSONResponse

from src.config import settings
from src.loystar_client import LoystarCredentials

_ALIAS_PATH = "/mcp-v2"
_ALIAS_METADATA_PATH = "/.well-known/oauth-protected-resource/mcp-v2"


def alias_resource() -> str:
    return f"{settings.canonical_server_origin}{_ALIAS_PATH}"


def install(app, core: ModuleType) -> None:
    """Install the fresh MCP resource once onto the clean FastAPI app."""
    if getattr(app.state, "claude_compat_installed", False):
        return

    canonical_resource = settings.canonical_mcp_resource

    def validate_oauth_resource(resource: str) -> str:
        if not resource:
            return canonical_resource
        if resource not in {canonical_resource, alias_resource()}:
            raise ValueError("resource must identify this MCP server")
        return resource

    def bearer_challenge(request: Request, scope: str = "loystar.read") -> str:
        if request.url.path == _ALIAS_PATH:
            metadata = f"{core.external_base_url(request)}{_ALIAS_METADATA_PATH}"
        else:
            metadata = f"{core.external_base_url(request)}/.well-known/oauth-protected-resource"
        return f'Bearer resource_metadata="{metadata}", scope="{scope}"'

    async def extract_loystar_credentials(request: Request) -> Optional[LoystarCredentials]:
        authorization = request.headers.get("authorization", "")
        if authorization.lower().startswith("bearer "):
            bearer = authorization.split(" ", 1)[1].strip()
            if bearer:
                expected_resource = (
                    alias_resource() if request.url.path == _ALIAS_PATH else canonical_resource
                )
                session = await request.app.state.oauth_store.resolve_token(
                    bearer,
                    expected_resource=expected_resource,
                )
                if session:
                    return session.credentials

        if settings.enable_legacy_routes:
            access_token = request.headers.get("x-loystar-access-token")
            client = request.headers.get("x-loystar-client")
            uid = request.headers.get("x-loystar-uid")
            expiry = request.headers.get("x-loystar-expiry")
            if all([access_token, client, uid, expiry]):
                return LoystarCredentials(
                    access_token=access_token or "",
                    client=client or "",
                    uid=uid or "",
                    expiry=expiry or "",
                    token_type=request.headers.get("x-loystar-token-type", "Bearer"),
                )
        return None

    # Existing OAuth/MCP handlers resolve these names at call time. Replacing
    # them here keeps one implementation of the critical OAuth flow while
    # extending the accepted protected-resource set explicitly.
    core.validate_oauth_resource = validate_oauth_resource
    core.bearer_challenge = bearer_challenge
    core.extract_loystar_credentials = extract_loystar_credentials

    async def alias_metadata(request: Request):
        return JSONResponse(
            content={
                "resource": alias_resource(),
                "authorization_servers": [core.oauth_issuer(request)],
                "scopes_supported": ["loystar.read", "offline_access"],
                "bearer_methods_supported": ["header"],
            },
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    app.add_api_route(
        _ALIAS_METADATA_PATH,
        alias_metadata,
        methods=["GET"],
        include_in_schema=False,
        name="oauth_protected_resource_metadata_v2",
    )
    app.add_api_route(
        _ALIAS_PATH,
        core.mcp_get,
        methods=["GET"],
        include_in_schema=False,
        name="mcp_get_v2",
    )
    app.add_api_route(
        _ALIAS_PATH,
        core.mcp_streamable_http,
        methods=["POST"],
        include_in_schema=False,
        name="mcp_streamable_http_v2",
    )

    async def validation_error(request: Request, exc: RequestValidationError):
        if request.url.path not in {"/mcp", _ALIAS_PATH}:
            return JSONResponse(status_code=422, content={"detail": exc.errors()})
        parse_error = any(error.get("type") == "json_invalid" for error in exc.errors())
        return JSONResponse(
            status_code=400,
            content={
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32700 if parse_error else -32600,
                    "message": "Parse error" if parse_error else "Invalid Request",
                },
            },
        )

    app.add_exception_handler(RequestValidationError, validation_error)
    app.state.claude_compat_installed = True
