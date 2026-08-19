# AI Platform Integration Guide

> Background integration material. `README.md` is the maintained source for
> the current OAuth, MCP, environment, and production configuration.

This project is a Loystar AI connector. It lets AI systems query merchant-owned Loystar business data through a controlled tool layer.

## Core Contract

AI platforms should call one of these server surfaces:

```text
POST /mcp
POST /mcp/tools/call
POST /mcp/rpc
GET  /mcp/tools
```

Use `POST /mcp` for standards-based remote MCP clients. The `/mcp/tools/*` and `/mcp/rpc` endpoints are helper/legacy surfaces for custom agents and demos.

The AI should not call Loystar APIs directly. This server owns:

- tool schemas
- merchant scoping
- Loystar API headers
- PII redaction
- future audit logging
- future approval/rate-limit policy

## Merchant Credentials

For a local live demo, the browser simulator can exchange a real Loystar test merchant email/password for session headers:

```text
POST /auth/loystar/sign_in
```

Body:

```json
{
  "email": "merchant@example.com",
  "password": "merchant-password"
}
```

The response includes the Loystar session headers needed for later tool calls. The password is not stored by this server. Use a test merchant account for demos.

For a single local merchant, credentials can live in `.env`.

For platform integrations, pass credentials per request:

```text
x-loystar-access-token: ...
x-loystar-client: ...
x-loystar-uid: merchant@example.com
x-loystar-expiry: ...
x-loystar-token-type: Bearer
```

The server uses these headers only for that request.

For remote MCP clients that support OAuth, connect the merchant through:

```text
GET  /.well-known/oauth-protected-resource
GET  /.well-known/oauth-authorization-server
GET  /oauth/authorize
POST /oauth/token
POST /mcp
```

The OAuth bridge lets any compatible AI host send the merchant to a Loystar login page, receive a bearer token, and call `/mcp` with `Authorization: Bearer ...`.

## Real Hosted AI Mounting Constraints

The local `/demo` page proves the full user journey, but actual ChatGPT, Claude, Gemini, and other hosted AI systems cannot call `http://127.0.0.1:8000` on your laptop. To mount this server into real hosted AI products, deploy it behind:

- a public HTTPS URL
- stable auth for the AI connector, usually `x-connector-api-key` or OAuth
- a secure merchant linking flow
- per-merchant token storage or token refresh
- a privacy policy and terms page if the platform requires them

The recommended production login pattern is OAuth or a secure Loystar token-exchange flow. Email/password exchange is acceptable for a controlled local demo or internal prototype, but it should not be the long-term production integration.

## Claude

Claude-compatible MCP clients should discover tools from:

```text
GET /mcp/tools
```

Then call tools through:

```text
POST /mcp/rpc
```

Example JSON-RPC body:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "loystar_get_sales",
    "arguments": {
      "from_date": "2025-01-01",
      "to_date": "2025-01-31",
      "page_number": 1,
      "page_size": 30
    }
  }
}
```

## ChatGPT

ChatGPT custom actions/connectors can call:

```text
POST /mcp/tools/call
```

Example body:

```json
{
  "name": "loystar_get_customers",
  "arguments": {
    "page_number": 1,
    "page_size": 30
  }
}
```

Connector auth should inject the merchant Loystar headers server-side. Do not ask the model to generate or store merchant tokens in conversation.

For a Custom GPT Action, expose this server through public HTTPS, import an OpenAPI schema for `/mcp/tools/call`, and configure connector authentication so ChatGPT sends only the connector secret. Your backend should attach the merchant's Loystar session headers.

## Gemini

Gemini function calling can map each MCP tool to a function declaration.

Recommended function names:

```text
loystar_get_customers
loystar_search_customers
loystar_get_sales
loystar_get_orders
loystar_get_products
loystar_get_product_categories
loystar_get_loyalty_programs
loystar_get_business_branches
loystar_get_invoices
loystar_get_sms_balance
loystar_get_current_subscription
```

The executor should call `/mcp/tools/call` with the selected function name and arguments.

Gemini does not directly "install" this local MCP server by itself. Your app or agent executor defines the functions, receives Gemini's selected function call, then calls this server.

## Custom Agents

Custom agents can use either:

```text
POST /mcp/tools/call
```

or:

```text
POST /mcp/rpc
```

Use `/mcp/tools` at startup to discover available tools and schemas.

## Safety Rules

- Keep Loystar credentials out of prompts and chat history.
- Send credentials as request headers from the connector/backend.
- Keep `LOYSTAR_REDACT_PII=true` unless raw PII is explicitly required and authorized.
- Prefer read-only tools for general AI Q&A.
- Put all write tools behind approval, audit logging, and rate limits.
