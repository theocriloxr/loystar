import base64
import hashlib

import pytest
from fastapi.testclient import TestClient

from src.config import Settings, settings
from src.main import app, validate_oauth_resource
from src.oauth_cimd import _client_from_metadata, _public_https
from src.oauth_store import OAuthStore


def test_canonical_origin_normalizes_only_scheme_and_host_case():
    configured = Settings(
        _env_file=None,
        MCP_SERVER_BASE_URL="HTTPS://Loystar-Production.UP.RAILWAY.APP/",
    )
    assert configured.canonical_server_origin == "https://loystar-production.up.railway.app"
    assert configured.canonical_mcp_resource.endswith("/mcp")


def test_resource_binding_is_exact(monkeypatch):
    monkeypatch.setattr(settings, "server_base_url", "https://bridge.example")
    assert validate_oauth_resource("") == "https://bridge.example/mcp"
    assert validate_oauth_resource("https://bridge.example/mcp") == "https://bridge.example/mcp"
    with pytest.raises(ValueError):
        validate_oauth_resource("https://attacker.example/mcp")


async def test_unknown_https_client_is_not_auto_registered(monkeypatch):
    async def no_cimd(_client_id):
        return None

    monkeypatch.setattr("src.oauth_cimd._resolve_cimd", no_cimd)
    store = OAuthStore()
    with pytest.raises(ValueError, match="unknown OAuth client"):
        await store.validate_client(
            "https://client.example/metadata",
            "https://attacker.example/callback",
        )
    assert await store.get_client("https://client.example/metadata") is None


def test_cimd_metadata_requires_exact_identity_and_redirect():
    client_id = "https://claude.ai/oauth/mcp-oauth-client-metadata"
    client = _client_from_metadata(
        client_id,
        {
            "client_id": client_id,
            "client_name": "Claude",
            "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        },
    )
    assert client.redirect_uris == ["https://claude.ai/api/mcp/auth_callback"]
    with pytest.raises(ValueError, match="mismatch"):
        _client_from_metadata(client_id, {"client_id": "https://evil.example"})


@pytest.mark.parametrize(
    "url",
    [
        "http://claude.ai/metadata",
        "https://user:pass@claude.ai/metadata",
        "https://claude.ai/metadata#fragment",
        "https://localhost/metadata",
    ],
)
def test_cimd_url_shape_rejects_unsafe_values(url):
    assert _public_https(url) is (url == "https://localhost/metadata")


def test_metadata_is_no_store_and_advertises_working_cimd():
    with TestClient(app) as client:
        protected = client.get("/.well-known/oauth-protected-resource")
        authorization = client.get("/.well-known/oauth-authorization-server")
    assert protected.headers["cache-control"] == "no-store"
    assert authorization.headers["cache-control"] == "no-store"
    assert authorization.json()["client_id_metadata_document_supported"] is True


def test_root_post_is_not_an_mcp_alias():
    with TestClient(app) as client:
        response = client.post("/", json={})
    assert response.status_code == 405


def test_get_mcp_challenges_before_transport_negotiation():
    with TestClient(app) as client:
        response = client.get("/mcp")
    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("Bearer resource_metadata=")


def test_authorize_accepts_consent_and_defaults_resource(monkeypatch):
    verifier = "a-secure-pkce-verifier-that-is-long-enough-1234567890"
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).decode("ascii").rstrip("=")
    with TestClient(app) as client:
        registration = client.post(
            "/oauth/register",
            json={
                "client_name": "Claude-like client",
                "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
                "token_endpoint_auth_method": "none",
            },
        ).json()
        response = client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": registration["client_id"],
                "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
                "scope": "loystar.read offline_access",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "prompt": "consent",
            },
        )
    assert response.status_code == 200
    assert f'value="{settings.canonical_mcp_resource}"' in response.text
