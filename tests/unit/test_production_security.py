import base64
import hashlib

import pytest
from fastapi.testclient import TestClient

from src.config import Settings, settings
from src.loystar_client import LoystarClient, LoystarCredentials
from src.main import app
from src.oauth_store import OAuthStore
from src.server import create_mcp_server


def _challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def test_production_configuration_fails_closed_without_durable_services():
    production = Settings(
        _env_file=None,
        ENVIRONMENT="production",
        MCP_SERVER_BASE_URL="https://loystar-mcp.example.com",
        ALLOWED_HOSTS="loystar-mcp.example.com",
        ALLOWED_ORIGINS="https://chatgpt.com",
        ENABLE_DEMO_ROUTES=False,
        ENABLE_LEGACY_ROUTES=False,
        ENABLE_PROTOTYPE_ROUTES=False,
        ENABLE_PROTOTYPE_TOOLS=False,
        ENABLE_BILLING_ROUTES=False,
        ALLOW_ENVIRONMENT_CREDENTIALS=False,
    )

    with pytest.raises(RuntimeError) as error:
        production.validate_for_startup()

    message = str(error.value)
    assert "DATABASE_URL is required" in message
    assert "REDIS_URL is required" in message
    assert "OAUTH_ENCRYPTION_KEY" in message
    assert "ADMIN_API_KEY" in message


async def test_oauth_store_binds_redirect_resource_and_rotates_refresh_tokens():
    store = OAuthStore()
    registered = await store.register_client(
        client_name="Security test",
        redirect_uris=["https://client.example/callback"],
    )
    client_id = registered["client_id"]
    credentials = LoystarCredentials(
        access_token="loystar-secret",
        client="loystar-client",
        uid="merchant@example.com",
        expiry="9999999999",
    )
    verifier = "a-secure-pkce-verifier-that-is-long-enough-1234567890"
    resource = "https://bridge.example/mcp"
    code = await store.create_code(
        credentials=credentials,
        redirect_uri="https://client.example/callback",
        client_id=client_id,
        code_challenge=_challenge(verifier),
        code_challenge_method="S256",
        scope="loystar.read offline_access",
        resource=resource,
    )

    with pytest.raises(ValueError):
        await store.exchange_code(
            code=code,
            redirect_uri="https://evil.example/callback",
            client_id=client_id,
            code_verifier=verifier,
            resource=resource,
        )

    # A redirect mismatch must not consume a valid authorization code.
    session = await store.exchange_code(
        code=code,
        redirect_uri="https://client.example/callback",
        client_id=client_id,
        code_verifier=verifier,
        resource=resource,
    )
    assert session.refresh_token
    old_access_token = session.access_token
    old_refresh_token = session.refresh_token

    rotated = await store.refresh(
        refresh_token=old_refresh_token,
        client_id=client_id,
        resource=resource,
    )
    assert rotated.refresh_token != old_refresh_token
    assert await store.resolve_token(old_access_token, resource) is None

    with pytest.raises(ValueError):
        await store.refresh(
            refresh_token=old_refresh_token,
            client_id=client_id,
            resource=resource,
        )

    await store.revoke_token(
        token=rotated.access_token,
        client_id=client_id,
    )
    assert await store.resolve_token(rotated.access_token, resource) is None


def test_untrusted_browser_origin_is_rejected():
    with TestClient(app) as client:
        response = client.post(
            "/mcp",
            headers={"Origin": "https://evil.example"},
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        )

    assert response.status_code == 403


def test_mcp_notification_returns_accepted():
    with TestClient(app) as client:
        response = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {},
            },
        )

    assert response.status_code == 401
    assert "resource_metadata=" in response.headers["www-authenticate"]


def test_mcp_rejects_non_json_content_type():
    with TestClient(app) as client:
        response = client.post(
            "/mcp",
            content='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}',
            headers={"content-type": "text/plain"},
        )

    assert response.status_code == 415


def test_mcp_rejects_malformed_json_with_jsonrpc_parse_error():
    with TestClient(app) as client:
        response = client.post(
            "/mcp",
            content="{not-json",
            headers={"content-type": "application/json"},
        )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == -32700


def test_raw_pii_override_is_not_advertised_by_default(monkeypatch):
    monkeypatch.setattr(settings, "allow_request_pii_override", False)
    server = create_mcp_server()

    for tool in server.list_tools()["tools"]:
        assert "include_pii" not in tool["inputSchema"].get("properties", {})


def test_loystar_redaction_covers_common_customer_identifiers():
    redacted = LoystarClient()._redact(
        {
            "customer_email": "merchant@example.com",
            "mobile_number": "+234 801 234 5678",
            "first_name": "Ada",
            "home_address": "1 Example Street",
            "date_of_birth": "1990-01-01",
            "access_token": "never-return-this",
            "product_name": "Coffee",
        }
    )

    assert redacted["customer_email"] == "me***@example.com"
    assert redacted["mobile_number"] == "***5678"
    assert redacted["first_name"] == "A***"
    assert redacted["home_address"] == "[redacted]"
    assert redacted["date_of_birth"] == "[redacted]"
    assert redacted["access_token"] == "[redacted]"
    assert redacted["product_name"] == "Coffee"
