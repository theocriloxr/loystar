import base64
import hashlib
import urllib.parse

from fastapi.testclient import TestClient

import src.main_clean as core
from main import app
from src.claude_compat import alias_resource
from src.loystar_client_clean import ResilientLoystarClient


def _challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _register(client: TestClient) -> dict:
    response = client.post(
        "/oauth/register",
        json={
            "client_name": "Claude fresh-resource test",
            "redirect_uris": ["https://client.example/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_mcp_v2_has_own_protected_resource_metadata_and_challenge():
    with TestClient(app, base_url="https://testserver") as client:
        challenge = client.post(
            "/mcp-v2",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        )
        metadata = client.get("/.well-known/oauth-protected-resource/mcp-v2")

    assert challenge.status_code == 401
    assert "/.well-known/oauth-protected-resource/mcp-v2" in challenge.headers[
        "www-authenticate"
    ]
    assert metadata.status_code == 200
    assert metadata.json()["resource"] == alias_resource()
    assert metadata.headers["cache-control"] == "no-store"


def test_mcp_v2_oauth_token_is_resource_bound(monkeypatch):
    async def fake_sign_in(self, email, password):
        return {
            "source": "loystar_api",
            "credentials": {
                "access_token": "upstream-access-v2",
                "client": "upstream-client-v2",
                "uid": "merchant-v2@example.com",
                "expiry": "9999999999",
                "token_type": "Bearer",
            },
            "merchant": {},
        }

    monkeypatch.setattr(ResilientLoystarClient, "sign_in", fake_sign_in)
    verifier = "claude-fresh-resource-pkce-verifier-abcdefghijklmnopqrstuvwxyz-0123456789"
    resource = alias_resource()

    with TestClient(app, base_url="https://testserver") as client:
        registration = _register(client)
        authorize = client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": registration["client_id"],
                "redirect_uri": "https://client.example/callback",
                "scope": "loystar.read offline_access",
                "code_challenge": _challenge(verifier),
                "code_challenge_method": "S256",
                "state": "fresh-state",
                "resource": resource,
                "prompt": "consent",
            },
        )
        assert authorize.status_code == 200, authorize.text

        callback = client.post(
            "/oauth/authorize",
            data={
                "response_type": "code",
                "client_id": registration["client_id"],
                "redirect_uri": "https://client.example/callback",
                "scope": "loystar.read offline_access",
                "code_challenge": _challenge(verifier),
                "code_challenge_method": "S256",
                "state": "fresh-state",
                "resource": resource,
                "email": "merchant-v2@example.com",
                "password": "not-stored",
                "decision": "approve",
            },
            follow_redirects=False,
        )
        assert callback.status_code == 303, callback.text
        callback_query = urllib.parse.parse_qs(
            urllib.parse.urlsplit(callback.headers["location"]).query
        )
        code = callback_query["code"][0]
        assert callback_query["state"] == ["fresh-state"]
        assert callback_query["iss"]

        token = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": registration["client_id"],
                "code": code,
                "redirect_uri": "https://client.example/callback",
                "code_verifier": verifier,
                "resource": resource,
            },
        )
        assert token.status_code == 200, token.text
        bearer = token.json()["access_token"]

        initialize_v2 = client.post(
            "/mcp-v2",
            headers={"Authorization": f"Bearer {bearer}"},
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "initialize",
                "params": {"protocolVersion": core.app.state.mcp_server.protocol_version},
            },
        )
        assert initialize_v2.status_code == 200, initialize_v2.text

        canonical = client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {bearer}"},
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "initialize",
                "params": {"protocolVersion": core.app.state.mcp_server.protocol_version},
            },
        )
        assert canonical.status_code == 401
