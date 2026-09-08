"""Secure OAuth Client ID Metadata Document (CIMD) resolution.

This module performs metadata-document resolution without monkeypatching the
OAuth store. It is deliberately side-effect free so the production OAuth path
can be reasoned about and tested directly.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import time
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_CACHE_LOCK = asyncio.Lock()
_CACHE_TTL_SECONDS = 300
_MAX_METADATA_BYTES = 64 * 1024
_MAX_URL_LENGTH = 2048


def _validate_redirect_uri(uri: str) -> None:
    if not uri or len(uri) > 512 or "*" in uri:
        raise ValueError("redirect_uri is invalid")
    parsed = urlparse(uri)
    if parsed.fragment or parsed.username or parsed.password:
        raise ValueError("redirect_uri cannot contain fragments or user information")
    is_loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and is_loopback):
        raise ValueError("redirect_uri must use HTTPS or an HTTP loopback address")
    if not parsed.hostname:
        raise ValueError("redirect_uri must include a host")


def _metadata_url_shape_is_safe(url: str) -> bool:
    parsed = urlparse(url)
    return (
        len(url) <= _MAX_URL_LENGTH
        and parsed.scheme == "https"
        and bool(parsed.hostname)
        and parsed.port in (None, 443)
        and not parsed.username
        and not parsed.password
        and not parsed.fragment
    )


def _host_is_public(hostname: str) -> bool:
    try:
        addresses = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except OSError:
        return False
    if not addresses:
        return False
    for address in addresses:
        try:
            ip = ipaddress.ip_address(address[4][0])
        except ValueError:
            return False
        if not ip.is_global:
            return False
    return True


def _normalize_metadata(client_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("client_id") != client_id:
        raise ValueError("client metadata client_id mismatch")

    client_name = payload.get("client_name")
    redirect_uris = payload.get("redirect_uris")
    if not isinstance(client_name, str) or not client_name or len(client_name) > 255:
        raise ValueError("invalid client_name")
    if not isinstance(redirect_uris, list) or not 1 <= len(redirect_uris) <= 10:
        raise ValueError("invalid redirect_uris")

    normalized_redirects: list[str] = []
    for uri in redirect_uris:
        if not isinstance(uri, str):
            raise ValueError("invalid redirect_uri")
        _validate_redirect_uri(uri)
        normalized_redirects.append(uri)

    grant_types = payload.get("grant_types", ["authorization_code", "refresh_token"])
    response_types = payload.get("response_types", ["code"])
    token_auth_method = payload.get("token_endpoint_auth_method", "none")

    if not isinstance(grant_types, list) or not all(isinstance(v, str) for v in grant_types):
        raise ValueError("invalid grant_types")
    if "authorization_code" not in grant_types:
        raise ValueError("client metadata must support authorization_code")
    supported_grants = [
        grant for grant in grant_types if grant in {"authorization_code", "refresh_token"}
    ]

    if not isinstance(response_types, list) or set(response_types) != {"code"}:
        raise ValueError("unsupported response_types")
    if token_auth_method != "none":
        raise ValueError("CIMD clients must use token_endpoint_auth_method=none")

    return {
        "client_id": client_id,
        "client_name": client_name,
        "redirect_uris": list(dict.fromkeys(normalized_redirects)),
        "grant_types": supported_grants,
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "client_secret_hash": None,
    }


async def resolve_cimd_client(client_id: str) -> Optional[dict[str, Any]]:
    """Resolve and validate an HTTPS Client ID Metadata Document.

    Returns ``None`` when the client_id is not a CIMD-shaped HTTPS URL. Unsafe
    or malformed HTTPS metadata IDs fail closed with ``ValueError``.
    """
    if not client_id.startswith("https://"):
        return None
    if not _metadata_url_shape_is_safe(client_id):
        raise ValueError("client metadata URL is invalid")

    hostname = urlparse(client_id).hostname
    if not hostname or not _host_is_public(hostname):
        raise ValueError("client metadata host is not publicly routable")

    now = time.monotonic()
    async with _CACHE_LOCK:
        cached = _CACHE.get(client_id)
        if cached and cached[0] > now:
            return dict(cached[1])

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(5.0, connect=3.0),
        follow_redirects=False,
        trust_env=False,
        headers={
            "Accept": "application/json",
            "User-Agent": "Loystar-MCP-OAuth/2.0",
        },
    ) as client:
        response = await client.get(client_id)

    if response.status_code != 200:
        raise ValueError("client metadata document unavailable")
    if len(response.content) > _MAX_METADATA_BYTES:
        raise ValueError("client metadata document too large")

    content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type not in {"application/json", "application/jrd+json", "text/json"}:
        raise ValueError("client metadata document must be JSON")

    try:
        payload = response.json()
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValueError("client metadata document is invalid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("client metadata document must be an object")

    normalized = _normalize_metadata(client_id, payload)
    async with _CACHE_LOCK:
        _CACHE[client_id] = (time.monotonic() + _CACHE_TTL_SECONDS, dict(normalized))
    return normalized
