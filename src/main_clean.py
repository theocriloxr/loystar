"""Clean production entrypoint for the Loystar remote MCP server.

This app intentionally keeps the critical path small: health, OAuth 2.1/DCR,
and Streamable HTTP MCP. Legacy demos, prototype HITL routes, and billing are
kept out of the authentication process and can continue to live behind the old
entrypoint while this core is validated.
"""
from __future__ import annotations

import base64
import hmac
import html
import logging
import urllib.parse
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from src.config import settings
from src.http_security import (
    MCPContentTypeMiddleware,
    OriginValidationMiddleware,
    ProductionHTTPSMiddleware,
    RequestBodyLimitMiddleware,
    SecurityHeadersMiddleware,
)
from src.loystar_client import LoystarAPIError, LoystarCredentials, current_loystar_credentials
from src.loystar_client_clean import ResilientLoystarClient
from src.oauth_store_clean import OAuthStore, normalize_scope
from src.security import AuditLog, RateLimiter, rate_limit_key, verify_connector_auth
from src.server import MCPRequest, MCPResponse, create_mcp_server

logger = logging.getLogger(__name__)


class JsonRpcRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    jsonrpc: str = "2.0"
    id: Optional[str | int] = None
    method: str
    params: Dict[str, Any] = Field(default_factory=dict)


class OAuthClientRegistrationRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    client_name: str = Field(default="Unknown Client", min_length=1, max_length=255)
    redirect_uris: list[str] = Field(..., min_length=1, max_length=10)
    grant_types: list[str] = Field(default_factory=lambda: ["authorization_code", "refresh_token"])
    response_types: list[str] = Field(default_factory=lambda: ["code"])
    token_endpoint_auth_method: str = "none"


def external_base_url(request: Request) -> str:
    configured = settings.canonical_server_origin
    if configured and "localhost" not in configured and "127.0.0.1" not in configured:
        return configured
    return str(request.base_url).rstrip("/")


def oauth_issuer(request: Request) -> str:
    return (settings.oauth_issuer or external_base_url(request)).rstrip("/")


def bearer_challenge(request: Request, scope: str = "loystar.read") -> str:
    metadata = f"{external_base_url(request)}/.well-known/oauth-protected-resource"
    return f'Bearer resource_metadata="{metadata}", scope="{scope}"'


def oauth_error(error: str, description: str, status_code: int = 400) -> JSONResponse:
    headers = {"Cache-Control": "no-store", "Pragma": "no-cache"}
    if error == "invalid_client" and status_code == 401:
        headers["WWW-Authenticate"] = 'Basic realm="Loystar OAuth token endpoint"'
    return JSONResponse(
        status_code=status_code,
        content={"error": error, "error_description": description},
        headers=headers,
    )


def validate_oauth_resource(resource: str) -> str:
    if not resource:
        return settings.canonical_mcp_resource
    if resource != settings.canonical_mcp_resource:
        raise ValueError("resource must identify this MCP server")
    return resource


def credentials_from_sign_in(result: Dict[str, Any]) -> LoystarCredentials:
    credentials = result["credentials"]
    return LoystarCredentials(
        access_token=credentials["access_token"],
        client=credentials["client"],
        uid=credentials["uid"],
        expiry=credentials["expiry"],
        token_type=credentials.get("token_type", "Bearer"),
    )


def _append_query(url: str, values: dict[str, str]) -> str:
    parsed = urllib.parse.urlsplit(url)
    existing = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    existing.extend(values.items())
    query = urllib.parse.urlencode(existing)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))


def _parse_basic_authorization(header: str) -> tuple[str, Optional[str]]:
    if not header.lower().startswith("basic "):
        return "", None
    try:
        decoded = base64.b64decode(header[6:].strip(), validate=True).decode("utf-8")
    except Exception as exc:
        raise ValueError("invalid client authentication") from exc
    if ":" not in decoded:
        raise ValueError("invalid client authentication")
    raw_id, raw_secret = decoded.split(":", 1)
    return urllib.parse.unquote_plus(raw_id), urllib.parse.unquote_plus(raw_secret)


async def extract_loystar_credentials(request: Request) -> Optional[LoystarCredentials]:
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        bearer = authorization.split(" ", 1)[1].strip()
        if bearer:
            session = await request.app.state.oauth_store.resolve_token(
                bearer,
                expected_resource=settings.canonical_mcp_resource,
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


async def enforce_connector_controls(request: Request) -> None:
    verify_connector_auth(request)
    await request.app.state.rate_limiter.check(rate_limit_key(request))


async def enforce_oauth_rate_limit(request: Request) -> None:
    await request.app.state.oauth_rate_limiter.check(rate_limit_key(request))


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.validate_for_startup()
    durable = bool(settings.database_url and settings.oauth_encryption_key)

    app.state.mcp_server = create_mcp_server()
    # Consolidate the useful fixes from the production branch without modifying
    # the old server implementation.
    app.state.mcp_server.tools.loystar = ResilientLoystarClient()

    app.state.oauth_store = OAuthStore(
        code_ttl_seconds=settings.oauth_code_ttl_seconds,
        token_ttl_seconds=settings.oauth_token_ttl_seconds,
        refresh_token_ttl_seconds=settings.oauth_refresh_token_ttl_seconds,
        use_database=durable,
    )
    await app.state.oauth_store.initialize()
    await app.state.oauth_store.register_static_clients(settings.oauth_static_clients)

    app.state.audit_log = AuditLog(settings.audit_log_max_events, use_database=durable)
    app.state.rate_limiter = RateLimiter(
        settings.rate_limit_requests,
        settings.rate_limit_window_seconds,
        redis_url=settings.redis_url,
        namespace="mcp-clean",
    )
    app.state.oauth_rate_limiter = RateLimiter(
        settings.oauth_rate_limit_requests,
        settings.rate_limit_window_seconds,
        redis_url=settings.redis_url,
        namespace="oauth-clean",
    )
    await app.state.rate_limiter.initialize()
    await app.state.oauth_rate_limiter.initialize()

    logger.info(
        "Starting clean Loystar MCP core version=%s durable_oauth=%s resource=%s",
        app.state.mcp_server.version,
        durable,
        settings.canonical_mcp_resource,
    )
    yield

    await app.state.rate_limiter.close()
    await app.state.oauth_rate_limiter.close()
    if durable:
        from src.database import close_db

        await close_db()


app = FastAPI(
    title="Loystar MCP Server",
    description="Merchant-scoped remote MCP bridge for Loystar",
    version="2.0.0-clean",
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None if settings.is_production else "/redoc",
    lifespan=lifespan,
)


@app.exception_handler(RequestValidationError)
async def request_validation_error(request: Request, exc: RequestValidationError):
    if request.url.path != "/mcp":
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


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "MCP-Protocol-Version",
        "MCP-Session-Id",
        "x-connector-api-key",
    ],
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
app.add_middleware(OriginValidationMiddleware)
app.add_middleware(MCPContentTypeMiddleware)
app.add_middleware(ProductionHTTPSMiddleware)
app.add_middleware(RequestBodyLimitMiddleware, max_bytes=settings.max_request_body_bytes)
app.add_middleware(SecurityHeadersMiddleware)


@app.get("/")
async def root():
    return {
        "name": "Loystar MCP Server",
        "version": "2.0.0-clean",
        "health": "/health",
        "mcp": "/mcp",
        "oauth_protected_resource": "/.well-known/oauth-protected-resource",
        "oauth_authorization_server": "/.well-known/oauth-authorization-server",
    }


@app.get("/live")
async def live():
    return {"status": "alive"}


@app.get("/health")
@app.get("/healthz")
async def health(request: Request):
    dependencies = {"postgresql": "not_required", "redis": "not_required"}
    if settings.is_production:
        try:
            from src.database import check_db

            await check_db()
            dependencies["postgresql"] = "ready"
            await request.app.state.rate_limiter.healthcheck()
            dependencies["redis"] = "ready"
        except Exception:
            return JSONResponse(
                status_code=503,
                content={"status": "unavailable", "dependencies": dependencies},
            )
    return {
        "status": "healthy",
        "server": "Loystar MCP Server",
        "version": "2.0.0-clean",
        "environment": settings.environment,
        "dependencies": dependencies,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/.well-known/oauth-protected-resource")
@app.get("/.well-known/oauth-protected-resource/mcp")
async def oauth_protected_resource_metadata(request: Request):
    return JSONResponse(
        content={
            "resource": settings.canonical_mcp_resource,
            "authorization_servers": [oauth_issuer(request)],
            "scopes_supported": ["loystar.read", "offline_access"],
            "bearer_methods_supported": ["header"],
        },
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


@app.get("/.well-known/oauth-authorization-server")
async def oauth_authorization_server_metadata(request: Request):
    issuer = oauth_issuer(request)
    metadata: dict[str, Any] = {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/oauth/authorize",
        "token_endpoint": f"{issuer}/oauth/token",
        "revocation_endpoint": f"{issuer}/oauth/revoke",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["loystar.read", "offline_access"],
        "token_endpoint_auth_methods_supported": [
            "none",
            "client_secret_post",
            "client_secret_basic",
        ],
        "authorization_response_iss_parameter_supported": True,
        "client_id_metadata_document_supported": settings.oauth_enable_cimd,
    }
    if settings.oauth_allow_dynamic_registration:
        metadata["registration_endpoint"] = f"{issuer}/oauth/register"
    return JSONResponse(
        content=metadata,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


@app.post("/oauth/register")
async def oauth_register(registration: OAuthClientRegistrationRequest, request: Request):
    if not settings.oauth_allow_dynamic_registration:
        raise HTTPException(status_code=404, detail="Not found.")
    await enforce_oauth_rate_limit(request)

    expected = settings.oauth_dcr_initial_access_token
    if expected:
        authorization = request.headers.get("authorization", "")
        provided = authorization.split(" ", 1)[1] if authorization.lower().startswith("bearer ") else ""
        if not provided or not hmac.compare_digest(provided, expected):
            return oauth_error("invalid_token", "Registration is not authorized.", 401)

    try:
        result = await request.app.state.oauth_store.register_client(
            client_name=registration.client_name,
            redirect_uris=registration.redirect_uris,
            grant_types=registration.grant_types,
            response_types=registration.response_types,
            token_endpoint_auth_method=registration.token_endpoint_auth_method,
        )
    except (ValueError, RuntimeError) as exc:
        logger.warning("OAuth DCR rejected error=%s", type(exc).__name__)
        return oauth_error("invalid_client_metadata", str(exc))

    logger.info(
        "OAuth DCR persisted client_prefix=%s redirect_count=%s auth_method=%s",
        result["client_id"][:20],
        len(result["redirect_uris"]),
        result["token_endpoint_auth_method"],
    )
    return JSONResponse(
        status_code=201,
        content=result,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


@app.get("/oauth/authorize", response_class=HTMLResponse)
async def oauth_authorize_page(
    request: Request,
    response_type: str,
    client_id: str,
    redirect_uri: str,
    state: Optional[str] = None,
    scope: str = "loystar.read",
    code_challenge: str = "",
    code_challenge_method: str = "S256",
    resource: str = "",
    prompt: Optional[str] = None,
):
    await enforce_oauth_rate_limit(request)
    if response_type != "code":
        return oauth_error("unsupported_response_type", "Only response_type=code is supported.")
    try:
        client = await request.app.state.oauth_store.validate_client(client_id, redirect_uri)
        normalized_scope = normalize_scope(scope)
        if prompt not in {None, "", "consent"}:
            raise ValueError("unsupported prompt value")
        normalized_resource = validate_oauth_resource(resource)
        if code_challenge_method != "S256" or not 43 <= len(code_challenge) <= 128:
            raise ValueError("S256 PKCE is required")
    except ValueError as exc:
        description = str(exc)
        if description == "unknown OAuth client":
            return oauth_error(
                "invalid_client",
                "Client not found. Re-register the OAuth client and try again.",
                400,
            )
        return oauth_error("invalid_request", description, 400)

    hidden = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state or "",
        "scope": normalized_scope,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "resource": normalized_resource,
    }
    hidden_html = "\n".join(
        f'<input type="hidden" name="{html.escape(key)}" value="{html.escape(value, quote=True)}" />'
        for key, value in hidden.items()
    )
    redirect_host = urllib.parse.urlparse(redirect_uri).hostname or "the requesting application"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Connect Loystar</title>
<style>
body{{margin:0;font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:#f6f7f9;color:#18202f}}
main{{max-width:430px;margin:8vh auto;background:#fff;border:1px solid #e4e7ec;border-radius:12px;padding:26px}}
h1{{margin:0 0 8px;font-size:24px}}p{{color:#667085;line-height:1.5}}
label{{display:block;font-size:13px;font-weight:700;margin:14px 0 6px}}
input{{box-sizing:border-box;width:100%;border:1px solid #cfd4dc;border-radius:8px;padding:11px;font:inherit}}
button{{margin-top:18px;width:100%;border:0;background:#155eef;color:#fff;border-radius:8px;padding:12px;font-weight:700;cursor:pointer}}
button.deny{{margin-top:8px;background:#fff;color:#344054;border:1px solid #d0d5dd}}
</style>
</head>
<body><main>
<h1>Connect Loystar</h1>
<p><strong>{html.escape(client.client_name)}</strong> is requesting read access to this Loystar merchant account. After approval you will return to <strong>{html.escape(redirect_host)}</strong>.</p>
<p>Your password is sent to Loystar for sign-in and is never stored by this MCP server.</p>
<form method="post" action="/oauth/authorize">
{hidden_html}
<label for="email">Loystar email</label><input id="email" name="email" autocomplete="username" required />
<label for="password">Loystar password</label><input id="password" name="password" type="password" autocomplete="current-password" required />
<button type="submit" name="decision" value="approve">Approve read access</button>
<button class="deny" type="submit" name="decision" value="deny" formnovalidate>Cancel</button>
</form></main></body></html>"""


@app.post("/oauth/authorize")
async def oauth_authorize_submit(
    request: Request,
    response_type: str = Form(...),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    state: str = Form(""),
    scope: str = Form("loystar.read"),
    code_challenge: str = Form(...),
    code_challenge_method: str = Form(...),
    resource: str = Form(...),
    email: str = Form(""),
    password: str = Form(""),
    decision: str = Form("approve"),
):
    await enforce_oauth_rate_limit(request)
    issuer = oauth_issuer(request)
    if response_type != "code":
        raise HTTPException(status_code=400, detail="Only response_type=code is supported")

    try:
        await request.app.state.oauth_store.validate_client(client_id, redirect_uri)
        normalized_scope = normalize_scope(scope)
        normalized_resource = validate_oauth_resource(resource)
        if code_challenge_method != "S256" or not 43 <= len(code_challenge) <= 128:
            raise ValueError("S256 PKCE is required")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid OAuth authorization request: {exc}")

    if decision == "deny":
        values = {"error": "access_denied", "iss": issuer}
        if state:
            values["state"] = state
        return RedirectResponse(
            _append_query(redirect_uri, values),
            status_code=303,
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )
    if decision != "approve" or not email or not password:
        raise HTTPException(status_code=400, detail="Merchant approval and credentials are required")

    try:
        sign_in = await ResilientLoystarClient().sign_in(email, password)
        code = await request.app.state.oauth_store.create_code(
            credentials=credentials_from_sign_in(sign_in),
            redirect_uri=redirect_uri,
            client_id=client_id,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            scope=normalized_scope,
            resource=normalized_resource,
        )
    except LoystarAPIError:
        raise HTTPException(status_code=400, detail="Loystar authorization failed")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid OAuth authorization request: {exc}")

    logger.info(
        "OAuth authorization code issued client_prefix=%s redirect_host=%s state_present=%s resource=%s",
        client_id[:20],
        urllib.parse.urlparse(redirect_uri).hostname or "unknown",
        bool(state),
        normalized_resource,
    )
    values = {"code": code, "iss": issuer}
    if state:
        values["state"] = state
    return RedirectResponse(
        _append_query(redirect_uri, values),
        status_code=303,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


async def _token_client_auth(request: Request, form: Any) -> tuple[str, Optional[str], str]:
    basic_id, basic_secret = _parse_basic_authorization(request.headers.get("authorization", ""))
    form_id = str(form.get("client_id") or "")
    form_secret = str(form.get("client_secret") or "") or None

    if basic_id:
        if form_secret:
            raise ValueError("multiple client authentication methods are not allowed")
        if form_id and form_id != basic_id:
            raise ValueError("client_id does not match HTTP Basic credentials")
        return basic_id, basic_secret, "client_secret_basic"
    if form_secret:
        return form_id, form_secret, "client_secret_post"
    return form_id, None, "none"


@app.post("/oauth/token")
async def oauth_token(request: Request):
    await enforce_oauth_rate_limit(request)
    form = await request.form()
    grant_type = str(form.get("grant_type") or "")
    try:
        client_id, client_secret, auth_method_used = await _token_client_auth(request, form)
    except ValueError:
        return oauth_error("invalid_client", "Client authentication failed.", 401)
    if not client_id:
        return oauth_error("invalid_client", "Client authentication is required.", 401)

    try:
        resource = validate_oauth_resource(str(form.get("resource") or ""))
        if grant_type == "authorization_code":
            session = await request.app.state.oauth_store.exchange_code(
                code=str(form.get("code") or ""),
                redirect_uri=str(form.get("redirect_uri") or ""),
                client_id=client_id,
                code_verifier=str(form.get("code_verifier") or "") or None,
                resource=resource,
                client_secret=client_secret,
                auth_method_used=auth_method_used,
            )
        elif grant_type == "refresh_token":
            session = await request.app.state.oauth_store.refresh(
                refresh_token=str(form.get("refresh_token") or ""),
                client_id=client_id,
                resource=resource,
                client_secret=client_secret,
                auth_method_used=auth_method_used,
            )
        else:
            return oauth_error("unsupported_grant_type", "Unsupported grant type.")
    except ValueError as exc:
        message = str(exc)
        if "client" in message and (
            "authentication" in message or "registered" in message or "public client" in message
        ):
            return oauth_error("invalid_client", "Client authentication failed.", 401)
        return oauth_error("invalid_grant", "The OAuth grant is invalid or expired.")
    except Exception:
        logger.exception("OAuth token service failure")
        return oauth_error("server_error", "Token service unavailable.", 503)

    payload: dict[str, Any] = {
        "access_token": session.access_token,
        "token_type": "Bearer",
        "expires_in": settings.oauth_token_ttl_seconds,
        "scope": session.scope,
    }
    if session.refresh_token:
        payload["refresh_token"] = session.refresh_token
    return JSONResponse(
        content=payload,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


@app.post("/oauth/revoke")
async def oauth_revoke(request: Request):
    await enforce_oauth_rate_limit(request)
    form = await request.form()
    try:
        client_id, client_secret, auth_method_used = await _token_client_auth(request, form)
        if not client_id:
            raise ValueError("client authentication failed")
        await request.app.state.oauth_store.revoke_token(
            token=str(form.get("token") or ""),
            client_id=client_id,
            client_secret=client_secret,
            auth_method_used=auth_method_used,
        )
    except ValueError:
        return oauth_error("invalid_client", "Client authentication failed.", 401)
    return Response(status_code=200, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


@app.get("/mcp")
async def mcp_get(request: Request):
    if not await extract_loystar_credentials(request):
        return JSONResponse(
            status_code=401,
            headers={"WWW-Authenticate": bearer_challenge(request)},
            content={"detail": "Authentication required."},
        )
    return Response(status_code=405, headers={"Allow": "POST"})


async def _dispatch_mcp(request: JsonRpcRequest) -> MCPResponse:
    server = app.state.mcp_server
    if request.method != "tools/call":
        return await server.handle_request(
            MCPRequest(
                id=str(request.id) if request.id is not None else None,
                method=request.method,
                params=request.params,
            )
        )

    try:
        structured = await server.call_tool(
            request.params.get("name"), request.params.get("arguments", {})
        )
        result = {
            "content": [
                {
                    "type": "text",
                    "text": __import__("json").dumps(
                        structured, ensure_ascii=False, separators=(",", ":")
                    ),
                }
            ],
            "structuredContent": structured,
            "isError": False,
        }
    except (LoystarAPIError, TypeError, ValueError) as exc:
        result = {
            "content": [{"type": "text", "text": str(exc)}],
            "isError": True,
        }
    return MCPResponse(id=str(request.id) if request.id is not None else None, result=result)


@app.post("/mcp")
async def mcp_streamable_http(request: JsonRpcRequest, http_request: Request):
    if request.jsonrpc != "2.0":
        raise HTTPException(status_code=400, detail="jsonrpc must be '2.0'")

    requested_protocol = http_request.headers.get("mcp-protocol-version")
    supported = app.state.mcp_server.supported_protocol_versions
    if requested_protocol and requested_protocol not in supported:
        raise HTTPException(status_code=400, detail="Unsupported MCP protocol version.")

    await enforce_connector_controls(http_request)
    credentials = await extract_loystar_credentials(http_request)
    tool_name = request.params.get("name") if request.method == "tools/call" else request.method
    if not credentials:
        await http_request.app.state.audit_log.record(
            http_request, tool_name, "error", "oauth_required"
        )
        return JSONResponse(
            status_code=401,
            headers={"WWW-Authenticate": bearer_challenge(http_request)},
            content={
                "jsonrpc": "2.0",
                "id": request.id,
                "error": {
                    "code": -32001,
                    "message": "Loystar account connection required.",
                    "data": {
                        "oauth_protected_resource": f"{external_base_url(http_request)}/.well-known/oauth-protected-resource"
                    },
                },
            },
        )

    context = current_loystar_credentials.set(credentials)
    try:
        response = await _dispatch_mcp(request)
    finally:
        current_loystar_credentials.reset(context)

    tool_error = bool(
        request.method == "tools/call" and response.result and response.result.get("isError")
    )
    await http_request.app.state.audit_log.record(
        http_request,
        tool_name,
        "error" if response.error or tool_error else "success",
    )

    protocol = requested_protocol or app.state.mcp_server.protocol_version
    if request.method == "initialize" and response.result:
        protocol = response.result.get("protocolVersion", protocol)
    headers = {"MCP-Protocol-Version": protocol}

    if request.id is None:
        return Response(status_code=202, headers=headers)

    content: Dict[str, Any] = {"jsonrpc": "2.0", "id": response.id}
    if response.error is not None:
        content["error"] = response.error
    else:
        content["result"] = response.result
    return JSONResponse(content=content, headers=headers)
