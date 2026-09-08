"""Durable OAuth integration tests for the clean MCP core.

These tests run only when RUN_DURABLE_OAUTH_TESTS=1 and use the configured
PostgreSQL database. They deliberately construct separate OAuthStore instances
to prove DCR clients, authorization codes, access tokens, and refresh rotation
survive process/store boundaries.
"""
from __future__ import annotations

import base64
import hashlib
import os

import pytest

from src.config import settings
from src.loystar_client import LoystarCredentials
from src.oauth_store_clean import OAuthStore

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_DURABLE_OAUTH_TESTS") != "1",
    reason="durable OAuth integration test disabled",
)


def _challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _store() -> OAuthStore:
    return OAuthStore(
        code_ttl_seconds=300,
        token_ttl_seconds=3600,
        refresh_token_ttl_seconds=2592000,
        use_database=True,
    )


async def test_dcr_code_token_and_refresh_survive_store_boundaries():
    assert settings.database_url, "DATABASE_URL must be configured"
    assert settings.oauth_encryption_key, "OAUTH_ENCRYPTION_KEY must be configured"

    redirect_uri = "https://client.example/durable-callback"
    resource = settings.canonical_mcp_resource
    verifier = "durable-pkce-verifier-abcdefghijklmnopqrstuvwxyz-0123456789"

    store1 = _store()
    await store1.initialize()
    registered = await store1.register_client(
        client_name="Durable OAuth integration test",
        redirect_uris=[redirect_uri],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        token_endpoint_auth_method="none",
    )
    client_id = registered["client_id"]

    # A fresh store instance must see the DCR client immediately.
    store2 = _store()
    await store2.initialize()
    client = await store2.get_client(client_id, allow_cimd=False)
    assert client is not None
    assert client.client_id == client_id
    assert redirect_uri in client.redirect_uris

    credentials = LoystarCredentials(
        access_token="durable-upstream-access",
        client="durable-upstream-client",
        uid="durable-merchant@example.com",
        expiry="9999999999",
        token_type="Bearer",
    )
    code = await store1.create_code(
        credentials=credentials,
        redirect_uri=redirect_uri,
        client_id=client_id,
        code_challenge=_challenge(verifier),
        code_challenge_method="S256",
        scope="loystar.read offline_access",
        resource=resource,
    )

    # A different store/process model exchanges the persisted code.
    session = await store2.exchange_code(
        code=code,
        redirect_uri=redirect_uri,
        client_id=client_id,
        code_verifier=verifier,
        resource=resource,
        auth_method_used="none",
    )
    assert session.refresh_token
    assert session.merchant_uid == credentials.uid

    # And another fresh store can resolve the persisted access token.
    store3 = _store()
    await store3.initialize()
    resolved = await store3.resolve_token(session.access_token, resource)
    assert resolved is not None
    assert resolved.merchant_uid == credentials.uid
    assert resolved.client_id == client_id
    assert resolved.resource == resource

    old_refresh = session.refresh_token
    rotated = await store3.refresh(
        refresh_token=old_refresh,
        client_id=client_id,
        resource=resource,
        auth_method_used="none",
    )
    assert rotated.refresh_token
    assert rotated.refresh_token != old_refresh

    # The consumed refresh token must remain unusable from yet another store.
    store4 = _store()
    await store4.initialize()
    with pytest.raises(ValueError, match="invalid or expired refresh token"):
        await store4.refresh(
            refresh_token=old_refresh,
            client_id=client_id,
            resource=resource,
            auth_method_used="none",
        )

    resolved_rotated = await store4.resolve_token(rotated.access_token, resource)
    assert resolved_rotated is not None
    assert resolved_rotated.merchant_uid == credentials.uid
