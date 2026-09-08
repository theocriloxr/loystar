"""OAuth interoperability hardening for registered MCP clients.

This module keeps client metadata/redirect validation separate from token-endpoint
client authentication. OAuth authorization requests must never require a client
secret in the browser URL, while token, refresh, and revocation requests still
authenticate confidential clients.

It also upgrades legacy 302 OAuth callback redirects to 303 See Other, prevents
caching, and adds the RFC 9207 ``iss`` response parameter expected by current
MCP authorization clients before they redeem an authorization code.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from typing import Any, Optional
from urllib.parse import parse_qs, parse_qsl, urlencode, urlparse, urlsplit, urlunsplit

import starlette.responses as starlette_responses

from src.config import settings
from src.oauth_store import OAuthStore, RegisteredClient

logger = logging.getLogger(__name__)

# oauth_cimd.install() runs before this module is installed, so this reference
# preserves CIMD resolution for URL-form client IDs.
_ORIGINAL_VALIDATE_CLIENT = OAuthStore.validate_client
_ORIGINAL_EXCHANGE_CODE = OAuthStore.exchange_code
_ORIGINAL_REFRESH = OAuthStore.refresh
_ORIGINAL_REVOKE_TOKEN = OAuthStore.revoke_token
_ORIGINAL_CREATE_CODE = OAuthStore.create_code
_ORIGINAL_REDIRECT_RESPONSE = starlette_responses.RedirectResponse
_ORIGINAL_JSON_RESPONSE = starlette_responses.JSONResponse


def _hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _client_label(client_id: str) -> str:
    parsed = urlparse(client_id)
    return parsed.hostname or "registered-client"


def _oauth_issuer() -> str:
    return (settings.oauth_issuer or settings.canonical_server_origin).rstrip("/")


def _with_authorization_response_issuer(url: str) -> str:
    """Add RFC 9207 ``iss`` to Loystar authorization responses only.

    Authorization codes issued by this service are prefixed with ``loy_code_``;
    denials use ``error=access_denied``. Restricting the rewrite to those values
    prevents the global Starlette response patch from modifying unrelated
    redirects elsewhere in the application.
    """
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    query = dict(pairs)
    code = query.get("code", "")
    is_oauth_callback = code.startswith("loy_code_") or query.get("error") == "access_denied"
    if not is_oauth_callback or "iss" in query:
        return url

    pairs.append(("iss", _oauth_issuer()))
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(pairs), parts.fragment)
    )


async def _validate_client_for_authorization(
    self: OAuthStore,
    client_id: str,
    redirect_uri: Optional[str] = None,
    client_secret: Optional[str] = None,
) -> RegisteredClient:
    """Validate client identity/redirect without authenticating a browser request.

    Confidential OAuth clients authenticate at the token endpoint, not at the
    authorization endpoint. The previous generic validator required a secret
    everywhere, causing a DCR client to register successfully and then fail the
    subsequent GET /oauth/authorize request.
    """
    client = await self.get_client(client_id)
    if client is not None:
        if redirect_uri is not None and redirect_uri not in client.redirect_uris:
            raise ValueError("redirect_uri is not registered for this client")
        return client

    # Preserve the existing CIMD resolver for HTTPS metadata-document client IDs.
    return await _ORIGINAL_VALIDATE_CLIENT(
        self,
        client_id,
        redirect_uri,
        client_secret,
    )


async def _authenticate_token_client(
    self: OAuthStore,
    client_id: str,
    client_secret: Optional[str],
) -> RegisteredClient:
    """Authenticate a client specifically for token-like endpoints."""
    if not client_id:
        raise ValueError("client authentication failed")

    client = await self.get_client(client_id)
    if client is None:
        # URL-form CIMD clients are public clients in the current implementation.
        return await _ORIGINAL_VALIDATE_CLIENT(self, client_id, None, client_secret)

    method = client.token_endpoint_auth_method or "none"
    if method == "none":
        return client

    if method in {"client_secret_post", "client_secret_basic"}:
        if not client_secret or not client.client_secret_hash:
            raise ValueError("client authentication failed")
        if not secrets.compare_digest(
            _hash_secret(client_secret),
            client.client_secret_hash,
        ):
            raise ValueError("client authentication failed")
        return client

    raise ValueError("unsupported token endpoint authentication method")


async def _exchange_code_with_client_auth(self: OAuthStore, **kwargs):
    await _authenticate_token_client(
        self,
        str(kwargs.get("client_id") or ""),
        kwargs.get("client_secret"),
    )
    return await _ORIGINAL_EXCHANGE_CODE(self, **kwargs)


async def _refresh_with_client_auth(self: OAuthStore, **kwargs):
    await _authenticate_token_client(
        self,
        str(kwargs.get("client_id") or ""),
        kwargs.get("client_secret"),
    )
    return await _ORIGINAL_REFRESH(self, **kwargs)


async def _revoke_with_client_auth(self: OAuthStore, **kwargs):
    await _authenticate_token_client(
        self,
        str(kwargs.get("client_id") or ""),
        kwargs.get("client_secret"),
    )
    return await _ORIGINAL_REVOKE_TOKEN(self, **kwargs)


async def _create_code_with_safe_logging(self: OAuthStore, **kwargs):
    code = await _ORIGINAL_CREATE_CODE(self, **kwargs)
    client_id = str(kwargs.get("client_id") or "")
    redirect_uri = str(kwargs.get("redirect_uri") or "")
    logger.info(
        "OAuth authorization code issued client=%s redirect_host=%s scope=%s resource=%s authorization_code_issued=true",
        _client_label(client_id),
        urlparse(redirect_uri).hostname or "unknown",
        str(kwargs.get("scope") or ""),
        str(kwargs.get("resource") or ""),
    )
    return code


class OAuthRedirectResponse(_ORIGINAL_REDIRECT_RESPONSE):
    """Normalize OAuth callbacks to 303, add RFC 9207 issuer, and prevent caching."""

    def __init__(
        self,
        url,
        status_code: int = 307,
        headers=None,
        background=None,
    ) -> None:
        response_headers = dict(headers or {})
        final_url = str(url)
        parsed_before = urlparse(final_url)
        query_before = parse_qs(parsed_before.query, keep_blank_values=True)
        is_oauth_callback = (
            query_before.get("code", [""])[0].startswith("loy_code_")
            or query_before.get("error", [""])[0] == "access_denied"
        )

        if is_oauth_callback:
            if status_code == 302:
                status_code = 303
            final_url = _with_authorization_response_issuer(final_url)
            response_headers.setdefault("Cache-Control", "no-store")
            response_headers.setdefault("Pragma", "no-cache")

            parsed = urlparse(final_url)
            query = parse_qs(parsed.query, keep_blank_values=True)
            logger.info(
                "OAuth authorization redirect redirect_host=%s state_present=%s issuer_present=%s authorization_code_issued=%s status=%s",
                parsed.hostname or "unknown",
                "state" in query and bool(query.get("state", [""])[0]),
                query.get("iss", [""])[0] == _oauth_issuer(),
                "code" in query,
                status_code,
            )

        super().__init__(
            final_url,
            status_code=status_code,
            headers=response_headers or None,
            background=background,
        )


class OAuthJSONResponse(_ORIGINAL_JSON_RESPONSE):
    """Advertise RFC 9207 support in authorization-server metadata."""

    def __init__(self, content: Any, *args, **kwargs) -> None:
        if isinstance(content, dict) and {
            "issuer",
            "authorization_endpoint",
            "token_endpoint",
        }.issubset(content):
            content = dict(content)
            content.setdefault("authorization_response_iss_parameter_supported", True)
        super().__init__(content, *args, **kwargs)


def install() -> None:
    """Install the compatibility layer exactly once."""
    if getattr(OAuthStore, "_loystar_client_compat_installed", False):
        return

    OAuthStore.validate_client = _validate_client_for_authorization
    OAuthStore.exchange_code = _exchange_code_with_client_auth
    OAuthStore.refresh = _refresh_with_client_auth
    OAuthStore.revoke_token = _revoke_with_client_auth
    OAuthStore.create_code = _create_code_with_safe_logging

    starlette_responses.RedirectResponse = OAuthRedirectResponse
    starlette_responses.JSONResponse = OAuthJSONResponse

    OAuthStore._loystar_client_compat_installed = True
