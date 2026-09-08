import base64
import hashlib
import urllib.parse

import pytest
from fastapi.testclient import TestClient

from src.config import settings
from src.loystar_client_clean import ResilientLoystarClient
from src.main_clean import app


@pytest.fixture(autouse=True)
def _isolate_unit_runtime(monkeypatch):
    """Keep clean-core unit tests out of live production infrastructure.

    Railway executes this suite in the production service environment during
    pre-deploy. The application middleware is already constructed with the
    configured production host allowlist, so requests use the configured
    canonical origin, while runtime dependencies are switched to development /
    in-memory mode for the duration of each test. This prevents deployment
    tests from creating OAuth clients/tokens in the production PostgreSQL
    database or depending on production Redis.
    """
    monkeypatch.setattr(settings, "environment", "development")
    monkeypatch.setattr(settings, "database_url", None)
    monkeypatch.setattr(settings, "redis_url", None)
    monkeypatch.setattr(settings, "oauth_encryption_key", None)


def _client() -> TestClient:
    # Use the configured canonical origin so TrustedHostMiddleware receives a
    # host that belongs to the real allowlist. In production this is HTTPS;
    # locally it remains the configured development origin.
    return TestClient(app, base_url=settings.canonical_server_origin)


def _verifier() -> str:
    return "clean-pkce-verifier-abcdefghijklmnopqrstuvwxyz-0123456789"


def _challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _registration(client: TestClient, auth_method: str = "none") -> dict:
    response = client.post(
        "/oauth/register",
        json={
            "client_name": "Clean MCP test client",
            "redirect_uris": ["https://client.example/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": auth_method,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _authorize_get(client: TestClient, registration: dict, verifier: str):
    return client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": registration["client_id"],
            "redirect_uri": "https://client.example/callback",
            "scope": "loystar.read offline_access",
            "code_challenge": _challenge(verifier),
            "code_challenge_method": "S256",
            "state": "state-123",
            "resource": settings.canonical_mcp_resource,
            "prompt": "consent",
        },
    )


def _authorize_post(client: TestClient, registration: dict, verifier: str):
    return client.post(
        "/oauth/authorize",
        data={
            "response_type": "code",
            "client_id": registration["client_id"],
            "redirect_uri": "https://client.example/callback",
            "scope": "loystar.read offline_access",
            "code_challenge": _challenge(verifier),
            "code_challenge_method": "S256",
            "state": "state-123",
            "resource": settings.canonical_mcp_resource,
            "email": "merchant@example.com",
            "password": "not-stored",
            "decision": "approve",
        },
        follow_redirects=False,
    )


def test_clean_metadata_health_and_mcp_challenge():
    with _client() as client:
        health = client.get("/healthz")
        metadata = client.get("/.well-known/oauth-authorization-server")
        mcp = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        )

    assert health.status_code == 200
    assert health.json()["version"] == "2.0.0-clean"
    assert metadata.status_code == 200
    assert metadata.headers["cache-control"] == "no-store"
    assert metadata.json()["authorization_response_iss_parameter_supported"] is True
    assert metadata.json()["client_id_metadata_document_supported"] is settings.oauth_enable_cimd
    assert mcp.status_code == 401
    assert "resource_metadata=" in mcp.headers["www-authenticate"]


def test_dcr_client_is_immediately_available_for_authorization():
    with _client() as client:
        registration = _registration(client)
        response = _authorize_get(client, registration, _verifier())

    assert response.status_code == 200
    assert registration["client_id"] in response.text


def test_public_dcr_oauth_flow_reaches_token_refresh_and_authenticated_mcp(monkeypatch):
    async def fake_sign_in(self, email, password):
        return {
            "source": "loystar_api",
            "credentials": {
                "access_token": "upstream-access",
                "client": "upstream-client",
                "uid": "merchant@example.com",
                "expiry": "9999999999",
                "token_type": "Bearer",
            },
            "merchant": {"email": "me***@example.com"},
        }

    monkeypatch.setattr(ResilientLoystarClient, "sign_in", fake_sign_in)
    verifier = _verifier()

    with _client() as client:
        registration = _registration(client)
        assert _authorize_get(client, registration, verifier).status_code == 200

        callback = _authorize_post(client, registration, verifier)
        assert callback.status_code == 303
        assert callback.headers["cache-control"] == "no-store"
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(callback.headers["location"]).query)
        assert query["state"] == ["state-123"]
        assert query["iss"]
        code = query["code"][0]

        token_response = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": registration["client_id"],
                "code": code,
                "redirect_uri": "https://client.example/callback",
                "code_verifier": verifier,
                "resource": settings.canonical_mcp_resource,
            },
        )
        assert token_response.status_code == 200, token_response.text
        token_payload = token_response.json()
        assert token_payload["access_token"].startswith("loy_at_")
        assert token_payload["refresh_token"].startswith("loy_rt_")

        initialize = client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {token_payload['access_token']}"},
            json={
                "jsonrpc": "2.0",
                "id": 7,
                "method": "initialize",
                "params": {"protocolVersion": app.state.mcp_server.protocol_version},
            },
        )
        assert initialize.status_code == 200, initialize.text
        assert initialize.json()["result"]["serverInfo"]["name"]

        refresh = client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "client_id": registration["client_id"],
                "refresh_token": token_payload["refresh_token"],
                "resource": settings.canonical_mcp_resource,
            },
        )
        assert refresh.status_code == 200, refresh.text
        rotated = refresh.json()
        assert rotated["refresh_token"] != token_payload["refresh_token"]

        replay = client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "client_id": registration["client_id"],
                "refresh_token": token_payload["refresh_token"],
                "resource": settings.canonical_mcp_resource,
            },
        )
        assert replay.status_code == 400
        assert replay.json()["error"] == "invalid_grant"


def test_confidential_client_secret_is_required_only_at_token_endpoint(monkeypatch):
    async def fake_sign_in(self, email, password):
        return {
            "source": "loystar_api",
            "credentials": {
                "access_token": "upstream-access",
                "client": "upstream-client",
                "uid": "merchant@example.com",
                "expiry": "9999999999",
                "token_type": "Bearer",
            },
            "merchant": {},
        }

    monkeypatch.setattr(ResilientLoystarClient, "sign_in", fake_sign_in)
    verifier = _verifier()

    with _client() as client:
        registration = _registration(client, "client_secret_basic")
        assert "client_secret" in registration
        # Authorization endpoint validates client + redirect without requiring a secret.
        assert _authorize_get(client, registration, verifier).status_code == 200
        callback = _authorize_post(client, registration, verifier)
        code = urllib.parse.parse_qs(
            urllib.parse.urlsplit(callback.headers["location"]).query
        )["code"][0]

        unauthenticated = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": registration["client_id"],
                "code": code,
                "redirect_uri": "https://client.example/callback",
                "code_verifier": verifier,
                "resource": settings.canonical_mcp_resource,
            },
        )
        assert unauthenticated.status_code == 401
        assert unauthenticated.json()["error"] == "invalid_client"

        raw = (
            urllib.parse.quote_plus(registration["client_id"])
            + ":"
            + urllib.parse.quote_plus(registration["client_secret"])
        )
        basic = base64.b64encode(raw.encode("utf-8")).decode("ascii")
        authenticated = client.post(
            "/oauth/token",
            headers={"Authorization": f"Basic {basic}"},
            data={
                "grant_type": "authorization_code",
                "client_id": registration["client_id"],
                "code": code,
                "redirect_uri": "https://client.example/callback",
                "code_verifier": verifier,
                "resource": settings.canonical_mcp_resource,
            },
        )
        assert authenticated.status_code == 200, authenticated.text


def test_denial_callback_is_303_and_contains_issuer():
    verifier = _verifier()
    with _client() as client:
        registration = _registration(client)
        response = client.post(
            "/oauth/authorize",
            data={
                "response_type": "code",
                "client_id": registration["client_id"],
                "redirect_uri": "https://client.example/callback",
                "scope": "loystar.read",
                "code_challenge": _challenge(verifier),
                "code_challenge_method": "S256",
                "state": "deny-state",
                "resource": settings.canonical_mcp_resource,
                "decision": "deny",
            },
            follow_redirects=False,
        )

    assert response.status_code == 303
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(response.headers["location"]).query)
    assert query["error"] == ["access_denied"]
    assert query["state"] == ["deny-state"]
    assert query["iss"]
