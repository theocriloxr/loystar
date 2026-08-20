import base64
import hashlib
import urllib.parse

from fastapi.testclient import TestClient

from src.config import settings
from src.main import app
from src.server import create_mcp_server


def test_mcp_server_lists_core_tools():
    server = create_mcp_server()

    result = server.list_tools()

    tool_names = {tool["name"] for tool in result["tools"]}
    assert "loystar_auth_status" in tool_names
    assert "loystar_get_customers" in tool_names
    assert "loystar_get_sales" in tool_names
    assert "loystar_get_products" in tool_names
    assert "loystar_get_loyalty_programs" in tool_names
    assert "calculate_churn_risk" in tool_names
    assert "generate_custom_coupon" in tool_names
    assert "dispatch_omnichannel_message" in tool_names
    assert "update_loyalty_points" in tool_names


async def test_loystar_auth_status_does_not_expose_secret_values():
    server = create_mcp_server()

    result = await server.call_tool("loystar_auth_status", {})

    assert "configured" in result
    assert "has_access_token" in result
    assert "access-token" not in result
    assert "client" not in result


async def test_mcp_server_reads_customer_profile_resource():
    server = create_mcp_server()

    result = await server.read_resource("loystar://customers/cust_demo/profile")

    assert result["uri"] == "loystar://customers/cust_demo/profile"
    assert result["content"]["customer_id"] == "cust_demo"
    assert result["content"]["loyalty_tier"] == "gold"


async def test_safe_coupon_is_created_without_approval():
    server = create_mcp_server()

    result = await server.call_tool(
        "generate_custom_coupon",
        {
            "customer_id": "cust_demo",
            "discount_percent": 10,
            "estimated_order_value": 100,
            "max_uses": 1,
        },
    )

    assert result["status"] == "created"
    assert result["coupon_code"].startswith("LOYCUST_DEM")


async def test_high_exposure_coupon_requires_hitl_approval():
    server = create_mcp_server()

    result = await server.call_tool(
        "generate_custom_coupon",
        {
            "customer_id": "cust_demo",
            "discount_percent": 50,
            "estimated_order_value": 500,
            "max_uses": 2,
        },
    )

    assert result["status"] == "pending_merchant_approval"
    assert result["risk_level"] == "escalated"
    assert result["financial_exposure"] == 500


def test_fastapi_demo_endpoints(monkeypatch):
    monkeypatch.setattr(settings, "admin_api_key", "test-admin-key")
    admin_headers = {"x-admin-api-key": "test-admin-key"}
    with TestClient(app) as client:
        root = client.get("/")
        assert root.status_code == 200
        assert root.json()["remote_mcp_url"] == "/mcp"
        assert root.json()["live_demo"] == "/demo"

        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["status"] == "healthy"

        tools = client.get("/mcp/tools", headers=admin_headers)
        assert tools.status_code == 200
        assert len(tools.json()["tools"]) >= 5

        profile = client.get("/api/v1/customers/cust_demo/profile", headers=admin_headers)
        assert profile.status_code == 200
        assert profile.json()["content"]["customer_id"] == "cust_demo"

        coupon = client.post(
            "/api/v1/customers/cust_demo/coupon",
            headers=admin_headers,
            json={
                "discount_percent": 10,
                "expiry_hours": 24,
                "estimated_order_value": 100,
            },
        )
        assert coupon.status_code == 200
        assert coupon.json()["status"] == "created"

        demo = client.get("/demo")
        assert demo.status_code == 200
        assert "Loystar AI Connector Demo" in demo.text

        protected_resource = client.get("/.well-known/oauth-protected-resource")
        assert protected_resource.status_code == 200
        assert protected_resource.json()["resource"].endswith("/mcp")

        authorization_server = client.get("/.well-known/oauth-authorization-server")
        assert authorization_server.status_code == 200
        assert authorization_server.json()["authorization_endpoint"].endswith("/oauth/authorize")


def test_fastapi_loystar_auth_status_can_use_request_headers():
    with TestClient(app) as client:
        response = client.post(
            "/mcp/tools/call",
            headers={
                "x-loystar-access-token": "test_access_token",
                "x-loystar-client": "test_client",
                "x-loystar-uid": "merchant@example.com",
                "x-loystar-expiry": "9999999999",
            },
            json={"name": "loystar_auth_status", "arguments": {}},
        )

    assert response.status_code == 200
    result = response.json()["result"]
    assert result["configured"] is True
    assert result["credential_source"] == "request_headers"
    assert "test_access_token" not in str(result)


def test_demo_chat_maps_natural_language_to_tool_call():
    with TestClient(app) as client:
        response = client.post(
            "/demo/chat",
            json={
                "host": "ChatGPT",
                "message": "Which customers look inactive or at churn risk?",
            },
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["tool_name"] == "calculate_churn_risk"
    assert payload["tool_result"]["customer_id"] == "cust_demo"


def test_loystar_sign_in_route_returns_session_headers(monkeypatch):
    async def fake_sign_in(self, email, password):
        assert email == "merchant@example.com"
        assert password == "secret"
        return {
            "source": "loystar_api",
            "credentials": {
                "access_token": "token_123",
                "client": "client_123",
                "uid": "merchant@example.com",
                "expiry": "9999999999",
                "token_type": "Bearer",
            },
            "merchant": {"email": "me***@example.com"},
        }

    monkeypatch.setattr("src.main.LoystarClient.sign_in", fake_sign_in)

    with TestClient(app) as client:
        response = client.post(
            "/auth/loystar/sign_in",
            json={"email": "merchant@example.com", "password": "secret"},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["credentials"]["access_token"] == "token_123"
    assert payload["credentials"]["client"] == "client_123"
    assert payload["credentials"]["uid"] == "merchant@example.com"


def test_oauth_linking_flow_issues_bearer_token_for_remote_mcp(monkeypatch):
    async def fake_sign_in(self, email, password):
        assert email == "merchant@example.com"
        assert password == "secret"
        return {
            "source": "loystar_api",
            "credentials": {
                "access_token": "token_123",
                "client": "client_123",
                "uid": "merchant@example.com",
                "expiry": "9999999999",
                "token_type": "Bearer",
            },
            "merchant": {"email": "me***@example.com"},
        }

    monkeypatch.setattr("src.main.LoystarClient.sign_in", fake_sign_in)

    verifier = "correct-horse-battery-staple-verifier-0123456789"
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .decode("ascii")
        .rstrip("=")
    )
    resource = settings.canonical_mcp_resource
    redirect_uri = "https://ai.example.com/oauth/callback"

    with TestClient(app) as client:
        registration = client.post(
            "/oauth/register",
            json={
                "client_name": "Test AI",
                "redirect_uris": [redirect_uri],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            },
        )
        assert registration.status_code == 201
        client_id = registration.json()["client_id"]

        authorize = client.post(
            "/oauth/authorize",
            data={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "state": "abc",
                "scope": "loystar.read offline_access",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": resource,
                "email": "merchant@example.com",
                "password": "secret",
            },
            follow_redirects=False,
        )
        assert authorize.status_code == 302
        location = authorize.headers["location"]
        assert location.startswith(f"{redirect_uri}?")
        code = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)["code"][0]

        token = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code": code,
                "code_verifier": verifier,
                "resource": resource,
            },
        )
        assert token.status_code == 200
        access_token = token.json()["access_token"]
        assert token.json()["refresh_token"].startswith("loy_rt_")

        mcp = client.post(
            "/mcp",
            headers={"authorization": f"Bearer {access_token}"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "loystar_auth_status", "arguments": {}},
            },
        )

    assert mcp.status_code == 200
    assert mcp.headers["mcp-protocol-version"] == "2025-11-25"
    result = mcp.json()["result"]["structuredContent"]
    assert result["configured"] is True
    assert result["credential_source"] == "request_headers"


def test_remote_mcp_prompts_oauth_when_loystar_not_connected(monkeypatch):
    monkeypatch.setattr(settings, "loystar_access_token", None)
    monkeypatch.setattr(settings, "loystar_client", None)
    monkeypatch.setattr(settings, "loystar_uid", None)
    monkeypatch.setattr(settings, "loystar_expiry", None)

    with TestClient(app) as client:
        response = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "loystar_get_sales", "arguments": {}},
            },
        )

    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers


def test_tool_calls_are_audited(monkeypatch):
    monkeypatch.setattr(settings, "admin_api_key", "test-admin-key")
    with TestClient(app) as client:
        call = client.post(
            "/mcp/tools/call",
            json={"name": "loystar_auth_status", "arguments": {}},
        )
        assert call.status_code == 200

        audit = client.get(
            "/admin/audit/events",
            headers={"x-admin-api-key": "test-admin-key"},
        )

    assert audit.status_code == 200
    events = audit.json()["events"]
    assert any(event["tool_name"] == "loystar_auth_status" for event in events)
    assert "access_token" not in str(events)


def test_connector_api_key_is_enforced_when_enabled(monkeypatch):
    monkeypatch.setattr(settings, "require_connector_auth", True)
    monkeypatch.setattr(settings, "connector_api_key", "demo-secret")

    with TestClient(app) as client:
        rejected = client.post(
            "/mcp/tools/call",
            json={"name": "loystar_auth_status", "arguments": {}},
        )
        accepted = client.post(
            "/mcp/tools/call",
            headers={"x-connector-api-key": "demo-secret"},
            json={"name": "loystar_auth_status", "arguments": {}},
        )

    assert rejected.status_code == 401
    assert accepted.status_code == 200


def test_rate_limiter_rejects_after_configured_limit(monkeypatch):
    monkeypatch.setattr(settings, "require_connector_auth", False)
    monkeypatch.setattr(settings, "rate_limit_requests", 1)
    monkeypatch.setattr(settings, "rate_limit_window_seconds", 60)

    with TestClient(app) as client:
        first = client.post(
            "/mcp/tools/call",
            json={"name": "loystar_auth_status", "arguments": {}},
        )
        second = client.post(
            "/mcp/tools/call",
            json={"name": "loystar_auth_status", "arguments": {}},
        )

    assert first.status_code == 200
    assert second.status_code == 429


def test_health_uses_initialized_rate_limiter():
    with TestClient(app) as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_streamable_mcp_initialize_and_tools_list():
    with TestClient(app) as client:
        initialize = client.post(
            "/mcp",
            headers={"MCP-Protocol-Version": "2025-11-25"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "test-client", "version": "1.0.0"},
                },
            },
        )
        assert initialize.status_code == 401
        assert "resource_metadata=" in initialize.headers["www-authenticate"]

        tools = client.post(
            "/mcp",
            headers={"MCP-Protocol-Version": "2025-11-25"},
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        assert tools.status_code == 401
        assert "WWW-Authenticate" in tools.headers
