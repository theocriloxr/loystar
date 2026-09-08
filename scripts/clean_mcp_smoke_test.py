"""Remote smoke test for the clean Loystar MCP core.

This script verifies the public protocol surface without merchant credentials:
health, RFC 9728 discovery, RFC 8414 metadata, MCP OAuth challenge, DCR, and an
authorization-page request using a fresh registered public client.

Usage:
    python scripts/clean_mcp_smoke_test.py https://loystar-production.up.railway.app
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import sys
from urllib.parse import urljoin

import httpx


def challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python scripts/clean_mcp_smoke_test.py <server-origin>", file=sys.stderr)
        return 2

    origin = sys.argv[1].rstrip("/")
    mcp_resource = f"{origin}/mcp"
    redirect_uri = "https://client.example/callback"
    verifier = secrets.token_urlsafe(48)[:64]

    with httpx.Client(timeout=15.0, follow_redirects=False) as client:
        health = client.get(f"{origin}/health")
        require(health.status_code == 200, f"health failed: {health.status_code} {health.text}")

        protected = client.get(f"{origin}/.well-known/oauth-protected-resource")
        require(protected.status_code == 200, "protected-resource discovery failed")
        protected_json = protected.json()
        require(protected_json.get("resource") == mcp_resource, "protected resource mismatch")
        require(protected.headers.get("cache-control") == "no-store", "metadata must be no-store")

        authorization = client.get(f"{origin}/.well-known/oauth-authorization-server")
        require(authorization.status_code == 200, "authorization-server discovery failed")
        authorization_json = authorization.json()
        require(authorization_json.get("issuer") == origin, "issuer mismatch")
        require(authorization_json.get("token_endpoint") == f"{origin}/oauth/token", "token endpoint mismatch")
        require(authorization_json.get("authorization_response_iss_parameter_supported") is True, "RFC 9207 support missing")

        unauthenticated = client.post(
            mcp_resource,
            headers={"Content-Type": "application/json"},
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        )
        require(unauthenticated.status_code == 401, f"unauthenticated MCP should be 401, got {unauthenticated.status_code}")
        require("resource_metadata=" in unauthenticated.headers.get("www-authenticate", ""), "MCP OAuth challenge missing")

        registration_endpoint = authorization_json.get("registration_endpoint")
        require(registration_endpoint, "DCR endpoint not advertised")
        registration = client.post(
            registration_endpoint,
            json={
                "client_name": "Loystar clean smoke test",
                "redirect_uris": [redirect_uri],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            },
        )
        require(registration.status_code == 201, f"DCR failed: {registration.status_code} {registration.text}")
        registered = registration.json()
        client_id = registered.get("client_id")
        require(client_id, "DCR response missing client_id")

        authorize = client.get(
            authorization_json["authorization_endpoint"],
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": "loystar.read offline_access",
                "code_challenge": challenge(verifier),
                "code_challenge_method": "S256",
                "state": "smoke-state",
                "resource": mcp_resource,
                "prompt": "consent",
            },
        )
        require(authorize.status_code == 200, f"fresh DCR client was not immediately authorizable: {authorize.status_code} {authorize.text}")
        require("Connect Loystar" in authorize.text, "authorization UI missing")

    print(
        json.dumps(
            {
                "status": "pass",
                "origin": origin,
                "resource": mcp_resource,
                "checks": [
                    "health",
                    "protected_resource_metadata",
                    "authorization_server_metadata",
                    "mcp_oauth_challenge",
                    "dynamic_client_registration",
                    "dcr_read_after_write",
                    "authorization_page",
                ],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
