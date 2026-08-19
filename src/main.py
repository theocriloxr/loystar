"""
FastAPI Application for Loystar MCP Server

This module provides the HTTP endpoints for the MCP server,
including SSE transport and webhook handlers.
"""
import asyncio
import hashlib
import hmac
import html
import json
import urllib.parse
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)

from src.config import settings
from src.http_security import (
    MCPContentTypeMiddleware,
    OriginValidationMiddleware,
    ProductionHTTPSMiddleware,
    RequestBodyLimitMiddleware,
    SecurityHeadersMiddleware,
)
from src.loystar_client import LoystarClient, LoystarCredentials, current_loystar_credentials
from src.oauth_store import OAuthStore, normalize_scope
from src.security import (
    AuditLog,
    RateLimiter,
    rate_limit_key,
    verify_admin_auth,
    verify_connector_auth,
)
from src.server import MCPServer, MCPRequest, create_mcp_server
from src.billing import router as billing_router


# Request/Response Models
class ToolCallRequest(BaseModel):
    """Tool call request model"""
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="Name of the tool to call")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Tool arguments")


class ResourceReadRequest(BaseModel):
    """Resource read request model"""
    model_config = ConfigDict(extra="forbid")

    uri: str = Field(..., description="Resource URI to read")


class JsonRpcRequest(BaseModel):
    """JSON-RPC 2.0 request body accepted by the HTTP transport."""
    model_config = ConfigDict(extra="forbid")

    jsonrpc: str = Field(default="2.0")
    id: Optional[str | int] = None
    method: str
    params: Dict[str, Any] = Field(default_factory=dict)


class MessageSendRequest(BaseModel):
    """Message send request model"""
    model_config = ConfigDict(extra="forbid")

    customer_id: str = Field(..., description="Customer ID")
    channel: str = Field(..., description="Channel: SMS, WHATSAPP, EMAIL")
    message_body: str = Field(..., description="Message content")


class CouponGenerateRequest(BaseModel):
    """Coupon generation request model"""
    model_config = ConfigDict(extra="forbid")

    customer_id: Optional[str] = Field(default=None, description="Customer ID")
    discount_percent: int = Field(..., ge=1, le=100, description="Discount percentage")
    expiry_hours: int = Field(default=24, ge=1, le=168, description="Expiry in hours")
    workspace_id: str = Field(default="default", description="Merchant workspace ID")
    estimated_order_value: float = Field(default=100.0, ge=0, description="Estimated order value")
    max_uses: int = Field(default=1, ge=1, description="Maximum coupon redemptions")
    target_count: int = Field(default=1, ge=1, description="Number of customers affected")


class DemoChatRequest(BaseModel):
    """Natural-language demo request from the browser AI host."""
    model_config = ConfigDict(extra="forbid")

    message: str = Field(..., min_length=1, description="Merchant question")
    host: str = Field(default="ChatGPT", description="AI host being simulated")


class LoystarSignInRequest(BaseModel):
    """Demo token-exchange request for linking a Loystar merchant account."""
    model_config = ConfigDict(extra="forbid")

    email: str = Field(..., description="Loystar merchant email")
    password: str = Field(..., description="Loystar merchant password")


class OAuthClientRegistrationRequest(BaseModel):
    """RFC 7591 fields supported by the public-client registration endpoint."""

    model_config = ConfigDict(extra="ignore")

    client_name: Optional[str] = Field(default="Unknown Client", max_length=255)
    redirect_uris: list[str] = Field(..., min_length=1, max_length=10)
    grant_types: list[str] = Field(
        default_factory=lambda: ["authorization_code", "refresh_token"]
    )
    response_types: list[str] = Field(default_factory=lambda: ["code"])
    token_endpoint_auth_method: str = Field(default="none")


async def extract_loystar_credentials(request: Request) -> Optional[LoystarCredentials]:
    """Read merchant-scoped Loystar credentials from connector request headers."""
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        bearer_token = auth_header.split(" ", 1)[1].strip()
        oauth_store = getattr(request.app.state, "oauth_store", None)
        if oauth_store:
            session = await oauth_store.resolve_token(
                bearer_token,
                expected_resource=settings.canonical_mcp_resource,
            )
            if session:
                return session.credentials

    if not settings.enable_legacy_routes:
        return None

    access_token = request.headers.get("x-loystar-access-token")
    client = request.headers.get("x-loystar-client")
    uid = request.headers.get("x-loystar-uid")
    expiry = request.headers.get("x-loystar-expiry")
    token_type = request.headers.get("x-loystar-token-type", "Bearer")

    if all([access_token, client, uid, expiry]):
        return LoystarCredentials(
            access_token=access_token or "",
            client=client or "",
            uid=uid or "",
            expiry=expiry or "",
            token_type=token_type,
        )

    return None


# Application State
class AppState:
    """Application state management"""
    mcp_server: MCPServer
    active_connections: list
    oauth_store: OAuthStore
    audit_log: AuditLog
    rate_limiter: RateLimiter
    oauth_rate_limiter: RateLimiter


# Lifespan context manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle"""
    settings.validate_for_startup()
    app.state.mcp_server = create_mcp_server()
    app.state.active_connections = []
    use_durable_state = bool(settings.database_url and settings.oauth_encryption_key)
    app.state.oauth_store = OAuthStore(
        code_ttl_seconds=settings.oauth_code_ttl_seconds,
        token_ttl_seconds=settings.oauth_token_ttl_seconds,
        refresh_token_ttl_seconds=settings.oauth_refresh_token_ttl_seconds,
        use_database=use_durable_state,
    )
    await app.state.oauth_store.initialize()
    await app.state.oauth_store.register_static_clients(settings.oauth_static_clients)
    app.state.audit_log = AuditLog(
        settings.audit_log_max_events,
        use_database=use_durable_state,
    )
    app.state.rate_limiter = RateLimiter(
        settings.rate_limit_requests,
        settings.rate_limit_window_seconds,
        redis_url=settings.redis_url,
        namespace="mcp",
    )
    app.state.oauth_rate_limiter = RateLimiter(
        settings.oauth_rate_limit_requests,
        settings.rate_limit_window_seconds,
        redis_url=settings.redis_url,
        namespace="oauth",
    )
    await app.state.rate_limiter.initialize()
    await app.state.oauth_rate_limiter.initialize()
    
    print(f"Starting {app.state.mcp_server.server_name} v{app.state.mcp_server.version}")
    print(f"Server ready at {settings.server_base_url}")
    if use_durable_state:
        print("OAuth store: PostgreSQL (encrypted at rest via AES-256-GCM)")
    else:
        print("OAuth store: in-memory development mode")
    
    yield
    
    await app.state.rate_limiter.close()
    await app.state.oauth_rate_limiter.close()
    if use_durable_state:
        from src.database import close_db

        await close_db()
    print("Shutting down MCP server...")


async def enforce_connector_controls(request: Request) -> None:
    """Apply auth and rate-limit policy to AI connector endpoints."""
    verify_connector_auth(request)
    await request.app.state.rate_limiter.check(rate_limit_key(request))


async def enforce_oauth_rate_limit(request: Request) -> None:
    await request.app.state.oauth_rate_limiter.check(rate_limit_key(request))


def require_feature(enabled: bool) -> None:
    if not enabled:
        raise HTTPException(status_code=404, detail="Not found.")


def require_prototype_admin(request: Request) -> None:
    require_feature(settings.enable_prototype_routes)
    verify_admin_auth(request)


def external_base_url(request: Request) -> str:
    """Return the public base URL AI hosts should use for OAuth discovery."""
    configured = settings.server_base_url.rstrip("/")
    if configured and "localhost" not in configured and "127.0.0.1" not in configured:
        return configured
    return str(request.base_url).rstrip("/")


def oauth_issuer(request: Request) -> str:
    """OAuth issuer URL for demo metadata."""
    return (settings.oauth_issuer or external_base_url(request)).rstrip("/")


def bearer_challenge(request: Request, scope: str = "loystar.read") -> str:
    """Build a WWW-Authenticate challenge for AI hosts that support OAuth discovery."""
    metadata_url = f"{external_base_url(request)}/.well-known/oauth-protected-resource"
    return f'Bearer resource_metadata="{metadata_url}", scope="{scope}"'


def oauth_error(
    error: str,
    description: str,
    status_code: int = 400,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": error, "error_description": description},
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


def validate_oauth_resource(resource: str) -> str:
    if resource != settings.canonical_mcp_resource:
        raise ValueError("resource must identify this MCP server")
    return resource


def credentials_from_sign_in(result: Dict[str, Any]) -> LoystarCredentials:
    """Convert Loystar sign-in response into request-scoped credentials."""
    credentials = result["credentials"]
    return LoystarCredentials(
        access_token=credentials["access_token"],
        client=credentials["client"],
        uid=credentials["uid"],
        expiry=credentials["expiry"],
        token_type=credentials.get("token_type", "Bearer"),
    )


def choose_demo_tool(message: str) -> Dict[str, Any]:
    """Map natural-language demo questions to safe MCP tools."""
    text = message.lower()

    if "auth" in text or "credential" in text or "connect" in text:
        return {"name": "loystar_auth_status", "arguments": {}}
    if "churn" in text or "inactive" in text or "risk" in text:
        return {"name": "calculate_churn_risk", "arguments": {"customer_id": "cust_demo"}}
    if "customer" in text:
        return {"name": "loystar_get_customers", "arguments": {"page_number": 1, "page_size": 10}}
    if "sale" in text or "revenue" in text or "transaction" in text:
        return {
            "name": "loystar_get_sales",
            "arguments": {"page_number": 1, "page_size": 10},
        }
    if "order" in text:
        return {"name": "loystar_get_orders", "arguments": {"page_number": 1, "page_size": 10}}
    if "product" in text or "inventory" in text or "stock" in text:
        return {"name": "loystar_get_products", "arguments": {"time_stamp": 0}}
    if "category" in text or "categories" in text:
        return {"name": "loystar_get_product_categories", "arguments": {"time_stamp": 0}}
    if "loyalty" in text or "program" in text or "reward" in text:
        return {"name": "loystar_get_loyalty_programs", "arguments": {"time_stamp": 0}}
    if "branch" in text or "location" in text:
        return {"name": "loystar_get_business_branches", "arguments": {}}
    if "invoice" in text or "unpaid" in text or "payment" in text:
        return {"name": "loystar_get_invoices", "arguments": {"status": "unpaid" if "unpaid" in text else None}}
    if "sms" in text or "message credit" in text:
        return {"name": "loystar_get_sms_balance", "arguments": {}}
    if "subscription" in text or "plan" in text:
        return {"name": "loystar_get_current_subscription", "arguments": {}}
    return {"name": "loystar_auth_status", "arguments": {}}


def demo_answer(host: str, tool_name: str, result: Dict[str, Any]) -> str:
    """Produce a short host-style answer for the live browser demo."""
    if result.get("configured") is False:
        return (
            f"{host} selected `{tool_name}`. The connector is working, but real Loystar "
            "merchant credentials are not configured yet. Add Loystar headers or .env values "
            "to query live merchant data."
        )

    if result.get("source") == "loystar_api":
        return (
            f"{host} selected `{tool_name}` and queried Loystar through the MCP gateway. "
            "The response below is returned through the controlled tool layer with PII masking."
        )

    return f"{host} selected `{tool_name}` and received a connector response."


# Create FastAPI app
app = FastAPI(
    title="Loystar MCP Server",
    description="Permissioned remote MCP bridge for merchant-scoped Loystar data",
    version="1.0.0",
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None if settings.is_production else "/redoc",
    lifespan=lifespan,
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
        "x-admin-api-key",
    ],
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
app.add_middleware(OriginValidationMiddleware)
app.add_middleware(MCPContentTypeMiddleware)
app.add_middleware(ProductionHTTPSMiddleware)
app.add_middleware(RequestBodyLimitMiddleware, max_bytes=settings.max_request_body_bytes)
app.add_middleware(SecurityHeadersMiddleware)

# Register billing router
app.include_router(billing_router)


# Health check endpoint
@app.get("/")
async def root():
    """Friendly landing response for demos and connector discovery."""
    result = {
        "name": "Loystar MCP Server",
        "purpose": "AI-platform agnostic MCP connector for merchant-scoped Loystar business data",
        "health": "/health",
        "remote_mcp_url": "/mcp",
        "oauth_protected_resource": "/.well-known/oauth-protected-resource",
        "oauth_authorization_server": "/.well-known/oauth-authorization-server",
    }
    if not settings.is_production:
        result["docs"] = "/docs"
    if settings.enable_legacy_routes:
        result["legacy_tools"] = "/mcp/tools"
        result["legacy_json_rpc"] = "/mcp/rpc"
    if settings.enable_demo_routes:
        result["live_demo"] = "/demo"
    return result


@app.get("/.well-known/oauth-protected-resource")
@app.get("/.well-known/oauth-protected-resource/mcp")
async def oauth_protected_resource_metadata(request: Request):
    """RFC 9728 metadata for the protected MCP resource."""
    issuer = oauth_issuer(request)
    return {
        "resource": settings.canonical_mcp_resource,
        "authorization_servers": [issuer],
        "scopes_supported": ["loystar.read", "offline_access"],
        "bearer_methods_supported": ["header"],
    }


@app.get("/.well-known/oauth-authorization-server")
async def oauth_authorization_server_metadata(request: Request):
    """RFC 8414 authorization-server metadata."""
    issuer = oauth_issuer(request)
    metadata = {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/oauth/authorize",
        "token_endpoint": f"{issuer}/oauth/token",
        "revocation_endpoint": f"{issuer}/oauth/revoke",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["loystar.read", "offline_access"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
    }
    if settings.oauth_allow_dynamic_registration:
        metadata["registration_endpoint"] = f"{issuer}/oauth/register"
    return metadata


@app.post("/oauth/register")
async def oauth_register(
    registration: OAuthClientRegistrationRequest,
    request: Request,
):
    """Register an MCP OAuth client using the supported RFC 7591 subset."""
    require_feature(settings.oauth_allow_dynamic_registration)
    await enforce_oauth_rate_limit(request)
    expected = settings.oauth_dcr_initial_access_token
    if expected:
        header = request.headers.get("authorization", "")
        provided = header.split(" ", 1)[1] if header.lower().startswith("bearer ") else ""
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
    except ValueError as exc:
        return oauth_error("invalid_client_metadata", str(exc))
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
):
    """Render a Loystar merchant login page for AI-host OAuth linking."""
    await enforce_oauth_rate_limit(request)
    if response_type != "code":
        raise HTTPException(status_code=400, detail="Only response_type=code is supported")
    try:
        client = await request.app.state.oauth_store.validate_client(
            client_id, redirect_uri
        )
        normalize_scope(scope)
        validate_oauth_resource(resource)
        if code_challenge_method != "S256" or not 43 <= len(code_challenge) <= 128:
            raise ValueError("S256 PKCE is required")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid OAuth authorization request")

    hidden_fields = {
        "response_type": response_type,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state or "",
        "scope": scope,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "resource": resource,
    }
    hidden_html = "\n".join(
        f'<input type="hidden" name="{html.escape(key)}" value="{html.escape(value, quote=True)}" />'
        for key, value in hidden_fields.items()
    )
    redirect_host = urllib.parse.urlparse(redirect_uri).hostname or redirect_uri
    return f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Connect Loystar</title>
  <style>
    body {{ margin: 0; font-family: Segoe UI, Arial, sans-serif; background: #f6f7f9; color: #18202f; }}
    main {{ max-width: 420px; margin: 8vh auto; background: white; border: 1px solid #e4e7ec; border-radius: 8px; padding: 24px; }}
    h1 {{ margin: 0 0 8px; font-size: 24px; }}
    p {{ color: #667085; line-height: 1.45; }}
    label {{ display: block; font-size: 13px; font-weight: 700; margin: 14px 0 6px; }}
    input {{ box-sizing: border-box; width: 100%; border: 1px solid #cfd4dc; border-radius: 6px; padding: 10px; font: inherit; }}
    button {{ margin-top: 18px; width: 100%; border: 0; background: #155eef; color: white; border-radius: 6px; padding: 11px 14px; font-weight: 700; cursor: pointer; }}
    button.deny {{ margin-top: 8px; background: transparent; color: #344054; border: 1px solid #d0d5dd; }}
  </style>
</head>
<body>
  <main>
    <h1>Connect Loystar</h1>
    <p><strong>{html.escape(client.client_name)}</strong> is requesting read access to this Loystar merchant account. After approval, the browser returns to <strong>{html.escape(redirect_host)}</strong>.</p>
    <p>The password is sent to Loystar for sign-in and is not stored by this server.</p>
    <form method="post" action="/oauth/authorize">
      {hidden_html}
      <label for="email">Loystar email</label>
      <input id="email" name="email" autocomplete="username" required />
      <label for="password">Loystar password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required />
      <button type="submit" name="decision" value="approve">Approve read access</button>
      <button class="deny" type="submit" name="decision" value="deny" formnovalidate>Cancel</button>
    </form>
  </main>
</body>
</html>
    """


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
    """Authenticate a Loystar merchant and redirect the AI host with an OAuth code."""
    await enforce_oauth_rate_limit(request)
    if response_type != "code":
        raise HTTPException(status_code=400, detail="Only response_type=code is supported")
    try:
        await request.app.state.oauth_store.validate_client(client_id, redirect_uri)
        normalized_scope = normalize_scope(scope)
        validate_oauth_resource(resource)
        if code_challenge_method != "S256":
            raise ValueError("S256 PKCE is required")
        if decision == "deny":
            query = {"error": "access_denied"}
            if state:
                query["state"] = state
            separator = "&" if "?" in redirect_uri else "?"
            return RedirectResponse(
                f"{redirect_uri}{separator}{urllib.parse.urlencode(query)}",
                status_code=302,
            )
        if decision != "approve" or not email or not password:
            raise ValueError("merchant approval and credentials are required")
        sign_in = await LoystarClient().sign_in(email, password)
        code = await request.app.state.oauth_store.create_code(
            credentials=credentials_from_sign_in(sign_in),
            redirect_uri=redirect_uri,
            client_id=client_id,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            scope=normalized_scope,
            resource=resource,
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid OAuth authorization request")
    except Exception:
        raise HTTPException(status_code=400, detail="Loystar authorization failed")

    query = {"code": code}
    if state:
        query["state"] = state
    separator = "&" if "?" in redirect_uri else "?"
    location = f"{redirect_uri}{separator}{urllib.parse.urlencode(query)}"
    return RedirectResponse(location, status_code=302)


@app.post("/oauth/token")
async def oauth_token(request: Request):
    """Exchange a code or rotate a refresh token."""
    await enforce_oauth_rate_limit(request)
    form = await request.form()
    grant_type = str(form.get("grant_type") or "")
    client_id = str(form.get("client_id") or "")
    client_secret = str(form.get("client_secret") or "") or None
    if not client_id:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.lower().startswith("basic "):
            import base64
            try:
                decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
                if ":" in decoded:
                    client_id, client_secret = decoded.split(":", 1)
            except Exception:
                pass
    resource = str(form.get("resource") or "")
    try:
        validate_oauth_resource(resource)
        if grant_type == "authorization_code":
            session = await request.app.state.oauth_store.exchange_code(
                code=str(form.get("code") or ""),
                redirect_uri=str(form.get("redirect_uri") or ""),
                client_id=client_id,
                code_verifier=str(form.get("code_verifier") or "") or None,
                resource=resource,
                client_secret=client_secret,
            )
        elif grant_type == "refresh_token":
            session = await request.app.state.oauth_store.refresh(
                refresh_token=str(form.get("refresh_token") or ""),
                client_id=client_id,
                resource=resource,
                client_secret=client_secret,
            )
        else:
            return oauth_error("unsupported_grant_type", "Unsupported grant type.")
    except ValueError:
        return oauth_error("invalid_grant", "The OAuth grant is invalid or expired.")
    except Exception:
        return oauth_error("server_error", "Token service unavailable.", 503)

    payload = {
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
    """Revoke an access or refresh token (RFC 7009 behaviour)."""
    await enforce_oauth_rate_limit(request)
    form = await request.form()
    try:
        await request.app.state.oauth_store.revoke_token(
            token=str(form.get("token") or ""),
            client_id=str(form.get("client_id") or ""),
            client_secret=str(form.get("client_secret") or "") or None,
        )
    except ValueError:
        # RFC 7009 returns 200 even when the token is already invalid.
        pass
    return Response(status_code=200, headers={"Cache-Control": "no-store"})


@app.get("/demo", response_class=HTMLResponse)
async def ai_connector_demo():
    require_feature(settings.enable_demo_routes)
    """Browser-based live demo that simulates mounting Loystar into an AI host."""
    return """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Loystar AI Connector Demo</title>
  <style>
    :root { color-scheme: light; font-family: Inter, Segoe UI, Arial, sans-serif; }
    body { margin: 0; background: #f6f7f9; color: #18202f; }
    header { background: #101828; color: white; padding: 28px 32px; }
    header h1 { margin: 0 0 8px; font-size: 28px; }
    header p { margin: 0; color: #d0d5dd; max-width: 820px; line-height: 1.5; }
    main { display: grid; grid-template-columns: 320px 1fr; gap: 18px; padding: 18px; }
    section, aside { background: white; border: 1px solid #e4e7ec; border-radius: 8px; }
    aside { padding: 18px; height: fit-content; }
    .panel { padding: 18px; }
    label { display: block; font-size: 13px; font-weight: 650; margin: 12px 0 6px; }
    input, select, textarea { box-sizing: border-box; width: 100%; border: 1px solid #cfd4dc; border-radius: 6px; padding: 10px; font: inherit; }
    textarea { min-height: 82px; resize: vertical; }
    button { border: 0; background: #155eef; color: white; border-radius: 6px; padding: 10px 14px; font-weight: 700; cursor: pointer; }
    button.secondary { background: #344054; }
    button:disabled { opacity: .65; cursor: wait; }
    .row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
    .pill { background: #eef4ff; color: #1849a9; border: 1px solid #c7d7fe; padding: 5px 8px; border-radius: 999px; font-size: 12px; font-weight: 700; }
    .chat { min-height: 420px; display: flex; flex-direction: column; gap: 12px; }
    .message { border-radius: 8px; padding: 12px; border: 1px solid #e4e7ec; }
    .user { background: #f8fafc; }
    .assistant { background: #f0fdf4; border-color: #bbf7d0; }
    pre { background: #101828; color: #f9fafb; padding: 12px; border-radius: 8px; overflow: auto; max-height: 260px; }
    .muted { color: #667085; font-size: 13px; line-height: 1.45; }
    .quick button { background: #eef4ff; color: #1849a9; margin: 4px 4px 0 0; }
    @media (max-width: 860px) { main { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <header>
    <h1>Loystar AI Connector Demo</h1>
    <p>Simulate mounting Loystar into ChatGPT, Claude, Gemini, or a custom agent. Ask a merchant question; the demo chooses a safe MCP tool, calls the gateway, and shows the result plus auditability.</p>
  </header>
  <main>
    <aside>
      <div class="pill">AI Host Simulator</div>
      <label for="host">AI system</label>
      <select id="host">
        <option>ChatGPT</option>
        <option>Claude</option>
        <option>Gemini</option>
        <option>Custom Agent</option>
      </select>
      <label for="loginEmail">Loystar email</label>
      <input id="loginEmail" placeholder="merchant@example.com" autocomplete="username" />
      <label for="loginPassword">Loystar password</label>
      <input id="loginPassword" type="password" placeholder="used only to fetch a session" autocomplete="current-password" />
      <p><button onclick="linkLoystar()">Link Loystar Account</button></p>
      <p class="muted">For live demos, this exchanges email/password for Loystar session headers and does not store the password.</p>
      <label for="accessToken">Loystar access token</label>
      <input id="accessToken" placeholder="optional for live Loystar calls" />
      <label for="client">Loystar client</label>
      <input id="client" placeholder="optional" />
      <label for="uid">Merchant UID</label>
      <input id="uid" placeholder="merchant@example.com" />
      <label for="expiry">Expiry</label>
      <input id="expiry" placeholder="token expiry" />
      <p class="muted">For a live boss demo without credentials, ask auth/status or use the mock churn/coupon guardrail. With real headers, the same UI queries live Loystar merchant data.</p>
      <div class="row">
        <button class="secondary" onclick="loadTools()">Show AI Tools</button>
        <button class="secondary" onclick="loadAudit()">Audit Log</button>
      </div>
    </aside>
    <section class="panel">
      <div class="row">
        <span class="pill">Merchant Question</span>
        <span class="muted">Examples: sales, customers, products, invoices, loyalty, SMS balance</span>
      </div>
      <label for="prompt">Ask Loystar via AI</label>
      <textarea id="prompt">What were my sales this month?</textarea>
      <div class="quick">
        <button onclick="setPrompt('Show my latest customers')">Customers</button>
        <button onclick="setPrompt('What were my sales this month?')">Sales</button>
        <button onclick="setPrompt('List my products and inventory')">Products</button>
        <button onclick="setPrompt('Show unpaid invoices')">Invoices</button>
        <button onclick="setPrompt('What loyalty programs are active?')">Loyalty</button>
        <button onclick="setPrompt('Which customers look inactive or at churn risk?')">Churn</button>
      </div>
      <p><button id="askBtn" onclick="ask()">Ask AI</button></p>
      <div id="chat" class="chat"></div>
    </section>
  </main>
  <script>
    function headers() {
      const h = {'Content-Type': 'application/json'};
      const accessToken = document.getElementById('accessToken').value.trim();
      const client = document.getElementById('client').value.trim();
      const uid = document.getElementById('uid').value.trim();
      const expiry = document.getElementById('expiry').value.trim();
      if (accessToken && client && uid && expiry) {
        h['x-loystar-access-token'] = accessToken;
        h['x-loystar-client'] = client;
        h['x-loystar-uid'] = uid;
        h['x-loystar-expiry'] = expiry;
      }
      return h;
    }
    function setPrompt(text) { document.getElementById('prompt').value = text; }
    function addMessage(kind, html) {
      const div = document.createElement('div');
      div.className = 'message ' + kind;
      div.innerHTML = html;
      document.getElementById('chat').prepend(div);
    }
    async function ask() {
      const button = document.getElementById('askBtn');
      button.disabled = true;
      const message = document.getElementById('prompt').value;
      const host = document.getElementById('host').value;
      addMessage('user', '<strong>' + host + ' user:</strong><br>' + escapeHtml(message));
      try {
        const res = await fetch('/demo/chat', {
          method: 'POST',
          headers: headers(),
          body: JSON.stringify({host, message})
        });
        const data = await res.json();
        addMessage('assistant',
          '<strong>' + host + ' using Loystar MCP:</strong><br>' +
          escapeHtml(data.answer || data.detail || 'No response') +
          '<p><span class="pill">Tool</span> ' + escapeHtml(data.tool_name || 'n/a') + '</p>' +
          '<pre>' + escapeHtml(JSON.stringify(data.tool_result || data, null, 2)) + '</pre>'
        );
      } catch (err) {
        addMessage('assistant', '<strong>Error:</strong> ' + escapeHtml(String(err)));
      } finally {
        button.disabled = false;
      }
    }
    async function linkLoystar() {
      const email = document.getElementById('loginEmail').value.trim();
      const password = document.getElementById('loginPassword').value;
      if (!email || !password) {
        addMessage('assistant', '<strong>Link Loystar:</strong> Enter email and password first.');
        return;
      }
      addMessage('user', '<strong>Merchant:</strong><br>Link my Loystar account for ' + escapeHtml(email));
      try {
        const res = await fetch('/auth/loystar/sign_in', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({email, password})
        });
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.detail || 'Loystar sign-in failed');
        }
        document.getElementById('accessToken').value = data.credentials.access_token || '';
        document.getElementById('client').value = data.credentials.client || '';
        document.getElementById('uid').value = data.credentials.uid || email;
        document.getElementById('expiry').value = data.credentials.expiry || '';
        document.getElementById('loginPassword').value = '';
        addMessage('assistant',
          '<strong>Loystar linked.</strong><br>The demo now has merchant session headers. Ask a business question next.' +
          '<pre>' + escapeHtml(JSON.stringify({uid: data.credentials.uid, expiry: data.credentials.expiry, token_type: data.credentials.token_type}, null, 2)) + '</pre>'
        );
      } catch (err) {
        addMessage('assistant', '<strong>Link failed:</strong> ' + escapeHtml(String(err.message || err)));
      }
    }
    async function loadTools() {
      const res = await fetch('/mcp/tools');
      const data = await res.json();
      addMessage('assistant', '<strong>AI-discoverable tools:</strong><pre>' + escapeHtml(JSON.stringify(data.tools.map(t => t.name), null, 2)) + '</pre>');
    }
    async function loadAudit() {
      const res = await fetch('/admin/audit/events');
      const data = await res.json();
      addMessage('assistant', '<strong>Recent audit events:</strong><pre>' + escapeHtml(JSON.stringify(data, null, 2)) + '</pre>');
    }
    function escapeHtml(value) {
      return String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    }
  </script>
</body>
</html>
    """


@app.post("/demo/chat")
async def demo_chat(request: DemoChatRequest, http_request: Request):
    require_feature(settings.enable_demo_routes)
    """Simulate an AI host choosing and invoking a Loystar MCP tool."""
    tool_call = choose_demo_tool(request.message)
    try:
        await enforce_connector_controls(http_request)
        token = current_loystar_credentials.set(await extract_loystar_credentials(http_request))
        try:
            result = await app.state.mcp_server.call_tool(
                tool_name=tool_call["name"],
                arguments=tool_call["arguments"],
            )
        finally:
            current_loystar_credentials.reset(token)

        await http_request.app.state.audit_log.record(http_request, tool_call["name"], "success")
        return {
            "host": request.host,
            "message": request.message,
            "tool_name": tool_call["name"],
            "tool_arguments": tool_call["arguments"],
            "answer": demo_answer(request.host, tool_call["name"], result),
            "tool_result": result,
        }
    except HTTPException:
        await http_request.app.state.audit_log.record(http_request, tool_call["name"], "error", "connector_policy_rejected")
        raise
    except Exception as e:
        await http_request.app.state.audit_log.record(
            http_request, tool_call["name"], "error", type(e).__name__
        )
        return {
            "host": request.host,
            "message": request.message,
            "tool_name": tool_call["name"],
            "tool_arguments": tool_call["arguments"],
            "answer": (
                f"{request.host} selected `{tool_call['name']}`, but the connector could not complete "
                f"the call: {e}"
            ),
            "tool_result": {"error": str(e)},
        }


@app.get("/live")
async def liveness_check():
    """Process liveness endpoint with no dependency checks."""
    return {"status": "alive"}


@app.get("/health")
async def health_check(request: Request):
    """Readiness endpoint; production checks PostgreSQL and Redis."""
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
        "version": "1.0.0",
        "environment": settings.environment,
        "dependencies": dependencies,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get("/admin/audit/events")
async def list_audit_events(request: Request, limit: int = 50):
    """List recent connector audit events for live demos and operations."""
    verify_admin_auth(request)
    return await request.app.state.audit_log.list_events(limit)


@app.post("/auth/loystar/sign_in")
async def loystar_sign_in(request: LoystarSignInRequest, http_request: Request):
    """
    Exchange merchant email/password for Loystar session headers.

    This route is designed for local demos and connector onboarding. The server
    does not store the merchant password.
    """
    require_feature(settings.enable_demo_routes)
    try:
        await enforce_connector_controls(http_request)
        result = await LoystarClient().sign_in(request.email, request.password)
        await http_request.app.state.audit_log.record(http_request, "loystar_sign_in", "success")
        return result
    except HTTPException:
        await http_request.app.state.audit_log.record(http_request, "loystar_sign_in", "error", "connector_policy_rejected")
        raise
    except Exception as e:
        await http_request.app.state.audit_log.record(
            http_request, "loystar_sign_in", "error", type(e).__name__
        )
        raise HTTPException(status_code=400, detail="Loystar sign-in failed.")


# MCP Protocol Endpoints
@app.get("/mcp")
async def mcp_sse(request: Request):
    """
    MCP Server-Sent Events endpoint for bidirectional communication.
    
    This endpoint supports SSE (Server-Sent Events) for streaming
    responses to connected AI clients.
    """
    require_feature(settings.enable_legacy_routes)
    await enforce_connector_controls(request)

    async def event_stream():
        endpoint = {"endpoint": "/mcp/rpc", "transport": "http-json-rpc"}
        yield f"event: endpoint\ndata: {json.dumps(endpoint)}\n\n"
        while True:
            if await request.is_disconnected():
                break
            yield f"event: ping\ndata: {json.dumps({'timestamp': datetime.now(timezone.utc).isoformat()})}\n\n"
            await asyncio.sleep(15)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.post("/mcp")
async def mcp_streamable_http(request: JsonRpcRequest, http_request: Request):
    """
    Remote MCP JSON-RPC endpoint for AI hosts.

    This path is the one to mount from ChatGPT, Claude, Gemini wrappers, Cursor,
    LangGraph, or any other remote MCP-capable client.
    """
    if request.jsonrpc != "2.0":
        raise HTTPException(status_code=400, detail="jsonrpc must be '2.0'")

    requested_protocol = http_request.headers.get("mcp-protocol-version")
    supported_protocols = app.state.mcp_server.supported_protocol_versions
    if requested_protocol and requested_protocol not in supported_protocols:
        raise HTTPException(status_code=400, detail="Unsupported MCP protocol version.")

    await enforce_connector_controls(http_request)
    tool_name = request.params.get("name") if request.method == "tools/call" else request.method
    credentials = await extract_loystar_credentials(http_request)

    public_methods = {"initialize", "notifications/initialized", "ping"}
    if (
        not credentials
        and not LoystarClient().is_configured()
        and request.method not in public_methods
    ):
        await http_request.app.state.audit_log.record(http_request, tool_name, "error", "oauth_required")
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

    token = current_loystar_credentials.set(credentials)
    try:
        response = await app.state.mcp_server.handle_request(
            MCPRequest(
                id=str(request.id) if request.id is not None else None,
                method=request.method,
                params=request.params,
            )
        )
        tool_result_error = bool(
            request.method == "tools/call"
            and response.result
            and response.result.get("isError")
        )
        status_value = "error" if response.error or tool_result_error else "success"
        await http_request.app.state.audit_log.record(http_request, tool_name, status_value)
    finally:
        current_loystar_credentials.reset(token)

    response_protocol = requested_protocol or app.state.mcp_server.protocol_version
    if request.method == "initialize" and response.result:
        response_protocol = response.result.get("protocolVersion", response_protocol)
    protocol_headers = {"MCP-Protocol-Version": response_protocol}
    if request.id is None:
        return Response(status_code=202, headers=protocol_headers)

    content: Dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": response.id,
    }
    if response.error is not None:
        content["error"] = response.error
    else:
        content["result"] = response.result

    return JSONResponse(
        content=content,
        headers=protocol_headers,
    )


# JSON-RPC 2.0 endpoint
@app.post("/mcp/rpc")
async def mcp_rpc(request: JsonRpcRequest, http_request: Request):
    """
    MCP JSON-RPC 2.0 endpoint for request/response interaction.
    """
    require_feature(settings.enable_legacy_routes)
    if request.jsonrpc != "2.0":
        raise HTTPException(status_code=400, detail="jsonrpc must be '2.0'")

    await enforce_connector_controls(http_request)
    tool_name = request.params.get("name") if request.method == "tools/call" else request.method

    token = current_loystar_credentials.set(await extract_loystar_credentials(http_request))
    try:
        response = await app.state.mcp_server.handle_request(
            MCPRequest(
                id=str(request.id) if request.id is not None else None,
                method=request.method,
                params=request.params,
            )
        )
        status_value = "error" if response.error else "success"
        await http_request.app.state.audit_log.record(http_request, tool_name, status_value)
    finally:
        current_loystar_credentials.reset(token)

    return JSONResponse(
        content={
            "jsonrpc": "2.0",
            "id": response.id,
            "result": response.result,
            "error": response.error
        }
    )


# List available tools
@app.get("/mcp/tools")
async def list_tools(request: Request):
    """List all available MCP tools"""
    require_feature(settings.enable_legacy_routes)
    verify_admin_auth(request)
    return app.state.mcp_server.list_tools()


# Call a tool
@app.post("/mcp/tools/call")
async def call_tool(request: ToolCallRequest, http_request: Request):
    """Call an MCP tool"""
    require_feature(settings.enable_legacy_routes)
    try:
        await enforce_connector_controls(http_request)
        token = current_loystar_credentials.set(await extract_loystar_credentials(http_request))
        try:
            result = await app.state.mcp_server.call_tool(
                tool_name=request.name,
                arguments=request.arguments
            )
        finally:
            current_loystar_credentials.reset(token)

        await http_request.app.state.audit_log.record(http_request, request.name, "success")
        return {"success": True, "result": result}
    except HTTPException:
        await http_request.app.state.audit_log.record(http_request, request.name, "error", "connector_policy_rejected")
        raise
    except Exception as e:
        await http_request.app.state.audit_log.record(
            http_request, request.name, "error", type(e).__name__
        )
        raise HTTPException(status_code=400, detail="Tool call failed.")


# List available resources
@app.get("/mcp/resources")
@app.post("/mcp/resources")
async def list_resources(request: Request):
    """List all available MCP resources"""
    require_feature(settings.enable_legacy_routes)
    verify_admin_auth(request)
    return app.state.mcp_server.list_resources()


# Read a resource
@app.post("/mcp/resources/read")
async def read_resource(request: ResourceReadRequest, http_request: Request):
    """Read an MCP resource"""
    require_feature(settings.enable_legacy_routes)
    verify_admin_auth(http_request)
    try:
        result = await app.state.mcp_server.read_resource(request.uri)
        return result
    except Exception:
        raise HTTPException(status_code=400, detail="Resource read failed.")


# HITL (Human-in-the-Loop) Endpoints
@app.post("/api/v1/hitl/request")
async def create_hitl_request(
    request: Request,
    action_type: str,
    action_data: Dict[str, Any],
    financial_exposure: float = 0.0,
    target_count: int = 1
):
    """
    Create a HITL approval request.
    
    This endpoint is used when the agent needs human approval
    for high-risk actions.
    """
    require_prototype_admin(request)
    # Check if auto-approval threshold is met
    if financial_exposure <= settings.hitl_auto_approve_threshold and target_count <= settings.hitl_campaign_size_threshold:
        return {
            "status": "auto_approved",
            "message": "Action falls within autonomous threshold"
        }
    
    # Create pending request
    request_id = f"hitl_{datetime.now(timezone.utc).timestamp()}"
    
    # In production, this would:
    # 1. Store the request in the database
    # 2. Send webhook to merchant for approval
    # 3. Add to Redis queue
    
    return {
        "request_id": request_id,
        "status": "pending_approval",
        "action_type": action_type,
        "financial_exposure": financial_exposure,
        "target_count": target_count,
        "created_at": datetime.now(timezone.utc).isoformat()
    }


# Approve HITL request
@app.post("/api/v1/hitl/approve/{request_id}")
async def approve_hitl_request(
    request_id: str, request: Request, approved: bool = True
):
    """Approve or reject a HITL request"""
    require_prototype_admin(request)
    # In production, this would update the database and resume the action
    
    return {
        "request_id": request_id,
        "status": "approved" if approved else "rejected",
        "updated_at": datetime.now(timezone.utc).isoformat()
    }


# Webhook Endpoints (for external integrations)
@app.post("/webhooks/stripe")
async def stripe_webhook(request: Request):
    """Handle the legacy Stripe webhook with signature verification."""
    require_feature(settings.enable_legacy_routes)
    if not settings.stripe_webhook_secret:
        raise HTTPException(status_code=503, detail="Stripe webhook is not configured.")
    payload = await request.body()
    signature = request.headers.get("stripe-signature", "")
    try:
        import stripe

        event = stripe.Webhook.construct_event(
            payload, signature, settings.stripe_webhook_secret
        )
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid Stripe webhook.")

    # Process events
    results = []
    event_type = event.get("type")
    if event_type in {"charge.succeeded", "customer.subscription.created"}:
        event_data = event.get("data", {}).get("object", {})
        results.append({
            "event": event_type,
            "status": "processed",
            "customer_id": event_data.get("customer"),
        })
    
    return {"received": True, "results": results}


@app.post("/webhooks/paystack")
async def paystack_webhook(request: Request):
    """Handle Paystack events only after SHA-512 signature verification."""
    require_feature(settings.enable_legacy_routes)
    if not settings.paystack_secret_key:
        raise HTTPException(status_code=503, detail="Paystack webhook is not configured.")
    raw_payload = await request.body()
    expected = hmac.new(
        settings.paystack_secret_key.encode("utf-8"),
        raw_payload,
        hashlib.sha512,
    ).hexdigest()
    provided = request.headers.get("x-paystack-signature", "")
    if not provided or not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=400, detail="Invalid Paystack webhook.")
    payload = json.loads(raw_payload)
    
    event = payload.get("event")
    
    if event == "charge.success":
        # Process successful charge
        data = payload.get("data", {})
        return {
            "received": True,
            "status": "processed",
            "customer_id": data.get("customer")
        }
    
    return {"received": True, "status": "ignored"}


# Customer Action Endpoints
@app.post("/api/v1/customers/{customer_id}/churn-risk")
async def calculate_churn_risk(customer_id: str, request: Request):
    """Calculate churn risk for a customer"""
    require_prototype_admin(request)
    result = await app.state.mcp_server.tools.calculate_churn_risk(
        customer_id=customer_id
    )
    return result


@app.post("/api/v1/customers/{customer_id}/coupon")
async def generate_coupon(
    customer_id: str, request: CouponGenerateRequest, http_request: Request
):
    """Generate a custom coupon for a customer"""
    require_prototype_admin(http_request)
    result = await app.state.mcp_server.tools.generate_custom_coupon(
        customer_id=request.customer_id or customer_id,
        discount_percent=request.discount_percent,
        expiry_hours=request.expiry_hours,
        workspace_id=request.workspace_id,
        estimated_order_value=request.estimated_order_value,
        max_uses=request.max_uses,
        target_count=request.target_count,
    )
    return result


@app.post("/api/v1/customers/{customer_id}/message")
async def send_message(
    customer_id: str, request: MessageSendRequest, http_request: Request
):
    """Send a message to a customer"""
    require_prototype_admin(http_request)
    result = await app.state.mcp_server.tools.dispatch_omnichannel_message(
        customer_id=customer_id,
        channel=request.channel,
        message_body=request.message_body
    )
    return result


@app.get("/api/v1/customers/{customer_id}/profile")
async def get_customer_profile(customer_id: str, request: Request):
    """Get customer profile"""
    require_prototype_admin(request)
    uri = f"loystar://customers/{customer_id}/profile"
    result = await app.state.mcp_server.read_resource(uri)
    return result


# Run the server
if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        app,
        host=settings.server_host,
        port=settings.server_port,
        reload=settings.log_level == "DEBUG"
    )
