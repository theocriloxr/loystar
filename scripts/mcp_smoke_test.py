#!/usr/bin/env python3
"""Small dependency-light smoke test for a deployed Loystar MCP server.

Usage:
  python scripts/mcp_smoke_test.py --base-url https://your-domain.up.railway.app

If you already have an OAuth access token:
  python scripts/mcp_smoke_test.py --base-url https://... --access-token "$TOKEN"
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request


def request_json(url: str, *, method: str = "GET", body: dict | None = None, headers: dict | None = None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Accept": "application/json",
        **({"Content-Type": "application/json"} if body is not None else {}),
        **(headers or {}),
    })
    with urllib.request.urlopen(req, timeout=20) as response:
        return response.status, dict(response.headers), json.loads(response.read())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("base_url_positional", nargs="?")
    parser.add_argument("--base-url")
    parser.add_argument("--access-token", "--token", dest="token")
    args = parser.parse_args()
    supplied_base = args.base_url or args.base_url_positional
    if not supplied_base:
        parser.error("provide --base-url")
    base = supplied_base.rstrip("/")

    checks = [
        ("live", f"{base}/live", "GET", None),
        ("health", f"{base}/health", "GET", None),
        ("protected-resource", f"{base}/.well-known/oauth-protected-resource", "GET", None),
        ("authorization-server", f"{base}/.well-known/oauth-authorization-server", "GET", None),
        ("initialize", f"{base}/mcp", "POST", {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "loystar-smoke-test", "version": "1.0.0"},
            },
        }),
        ("tools-list", f"{base}/mcp", "POST", {
            "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {},
        }),
    ]

    for name, url, method, body in checks:
        try:
            status, headers, payload = request_json(
                url,
                method=method,
                body=body,
                headers=(
                    {"Authorization": f"Bearer {args.token}", "MCP-Protocol-Version": "2025-11-25"}
                    if args.token and name in {"initialize", "tools-list"}
                    else {}
                ),
            )
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            if name == "initialize" and not args.token and exc.code == 401:
                challenge = exc.headers.get("WWW-Authenticate", "")
                if "resource_metadata=" not in challenge:
                    print("[FAIL] initialize: OAuth challenge lacks resource metadata")
                    return 1
                print("[PASS] MCP unauthenticated challenge advertises OAuth")
                continue
            if name == "tools-list" and not args.token:
                continue
            print(f"[FAIL] {name}: HTTP {exc.code} {detail}")
            return 1
        except Exception as exc:
            print(f"[FAIL] {name}: {exc}")
            return 1

        if name == "tools-list" and not args.token:
            continue

        if status != 200:
            print(f"[FAIL] {name}: HTTP {status}")
            return 1

        if name == "tools-list":
            names = {tool["name"] for tool in payload.get("result", {}).get("tools", [])}
            required = {"loystar_auth_status", "loystar_get_customers", "loystar_get_sales"}
            if not required.issubset(names):
                print(f"[FAIL] {name}: missing expected tools")
                return 1
        print(f"[PASS] {name}")

    if args.token:
        status, _, payload = request_json(
            f"{base}/mcp",
            method="POST",
            body={
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "loystar_auth_status", "arguments": {}},
            },
            headers={
                "Authorization": f"Bearer {args.token}",
                "MCP-Protocol-Version": "2025-11-25",
            },
        )
        if status != 200:
            print(f"[FAIL] authenticated-tool-call: HTTP {status}")
            return 1
        if "access_token" in json.dumps(payload):
            print("[FAIL] authenticated-tool-call: secret leaked in response")
            return 1
        print("[PASS] authenticated-tool-call")

    print("Smoke test completed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
