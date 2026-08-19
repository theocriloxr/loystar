"""MCP OAuth Client ID Metadata Document (CIMD) compatibility."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import time
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

from src.oauth_store import OAuthStore, RegisteredClient, validate_redirect_uri


_CACHE: dict[str, tuple[float, RegisteredClient]] = {}
_LOCK = asyncio.Lock()
_TTL = 300
_MAX_BYTES = 64 * 1024


def _public_https(url: str) -> bool:
    parsed = urlparse(url)
    return (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and not parsed.username
        and not parsed.password
        and not parsed.fragment
        and len(url) <= 2048
    )


def _public_host(hostname: str) -> bool:
    try:
        infos = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except OSError:
        return False

    if not infos:
        return False

    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            return False

        if not ip.is_global:
            return False

    return True


def _client_from_metadata(
    client_id: str,
    data: dict[str, Any],
) -> RegisteredClient:

    if data.get("client_id") != client_id:
        raise ValueError("client metadata client_id mismatch")

    name = data.get("client_name")
    redirects = data.get("redirect_uris")

    if not isinstance(name, str) or not name or len(name) > 255:
        raise ValueError("invalid client_name")

    if not isinstance(redirects, list) or not 1 <= len(redirects) <= 10:
        raise ValueError("invalid redirect_uris")

    normalized_redirects: list[str] = []

    for uri in redirects:
        if not isinstance(uri, str):
            raise ValueError("invalid redirect_uri")

        validate_redirect_uri(uri)
        normalized_redirects.append(uri)

    grants = data.get(
        "grant_types",
        ["authorization_code", "refresh_token"],
    )

    responses = data.get(
        "response_types",
        ["code"],
    )

    auth_method = data.get(
        "token_endpoint_auth_method",
        "none",
    )

    if not isinstance(grants, list):
        raise ValueError("invalid grant_types")

    if not set(grants).issubset(
        {"authorization_code", "refresh_token"}
    ):
        raise ValueError("unsupported grant_types")

    if not isinstance(responses, list) or set(responses) != {"code"}:
        raise ValueError("unsupported response_types")

    if auth_method not in {
        "none",
        "client_secret_post",
        "client_secret_basic",
    }:
        raise ValueError(
            "unsupported token_endpoint_auth_method"
        )

    return RegisteredClient(
        client_id=client_id,
        client_name=name,
        redirect_uris=list(dict.fromkeys(normalized_redirects)),
        grant_types=list(grants),
        response_types=list(responses),
        token_endpoint_auth_method=auth_method,
        client_secret_hash=None,
    )


async def _resolve_cimd(
    client_id: str,
) -> Optional[RegisteredClient]:

    if not _public_https(client_id):
        return None

    hostname = urlparse(client_id).hostname

    if not hostname or not _public_host(hostname):
        raise ValueError(
            "client metadata host is not publicly routable"
        )

    now = time.monotonic()

    async with _LOCK:
        cached = _CACHE.get(client_id)

        if cached and cached[0] > now:
            return cached[1]

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(5.0, connect=3.0),
        follow_redirects=False,
        trust_env=False,
        headers={
            "Accept": "application/json",
            "User-Agent": "Loystar-MCP-OAuth/1.0",
        },
    ) as client:

        response = await client.get(client_id)

    if response.status_code != 200:
        raise ValueError(
            "client metadata document unavailable"
        )

    if len(response.content) > _MAX_BYTES:
        raise ValueError(
            "client metadata document too large"
        )

    content_type = (
        response.headers
        .get("content-type", "")
        .split(";", 1)[0]
        .strip()
        .lower()
    )

    if content_type not in {
        "application/json",
        "application/jrd+json",
        "text/json",
    }:
        raise ValueError(
            "client metadata document must be JSON"
        )

    try:
        data = response.json()
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValueError(
            "client metadata document is invalid JSON"
        ) from exc

    if not isinstance(data, dict):
        raise ValueError(
            "client metadata document must be an object"
        )

    registered = _client_from_metadata(
        client_id,
        data,
    )

    async with _LOCK:
        _CACHE[client_id] = (
            time.monotonic() + _TTL,
            registered,
        )

    return registered


_ORIGINAL_VALIDATE = OAuthStore.validate_client


async def _validate_client_with_cimd(
    self: OAuthStore,
    client_id: str,
    redirect_uri: Optional[str] = None,
    client_secret: Optional[str] = None,
) -> RegisteredClient:

    try:
        return await _ORIGINAL_VALIDATE(
            self,
            client_id,
            redirect_uri,
            client_secret,
        )

    except ValueError as original_error:

        if not client_id.startswith("https://"):
            raise original_error

        client = await _resolve_cimd(client_id)

        if client is None:
            raise original_error

        if (
            redirect_uri is not None
            and redirect_uri not in client.redirect_uris
        ):
            raise ValueError(
                "redirect_uri is not registered for this client"
            )

        if client.token_endpoint_auth_method != "none":
            raise ValueError(
                "CIMD clients must use token_endpoint_auth_method=none"
            )

        return client


def install() -> None:

    if getattr(
        OAuthStore,
        "_loystar_cimd_installed",
        False,
    ):
        return

    OAuthStore.validate_client = (
        _validate_client_with_cimd
    )

    OAuthStore._loystar_cimd_installed = True
