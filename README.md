# Loystar MCP Server

I built this project as a permissioned bridge between a merchant's Loystar account and MCP-compatible AI assistants. Once a merchant approves a connection, clients such as ChatGPT, Claude, Perplexity, and other remote MCP hosts can query that merchant's live Loystar business data without putting Loystar credentials in a prompt.

The production profile is deliberately read-only. It exposes real Loystar customers, sales, orders, products, product categories, loyalty programmes, branches, invoices, SMS balance, and subscription data. The older coupon, messaging, points, churn, billing, demo, and helper routes are development prototypes and production startup refuses to enable them.

## How it works

```text
AI assistant
    |
    |  MCP over HTTPS + merchant OAuth bearer token
    v
Loystar MCP Server
    |
    |  encrypted merchant-scoped Loystar session
    v
Loystar API
```

The AI client never receives the merchant's Loystar password or Loystar session headers. The password is sent to Loystar during the authorization screen, then discarded. The resulting Loystar session is encrypted with AES-GCM before it is stored.

Each OAuth token is:

- issued only to a registered client and exact redirect URI;
- protected with S256 PKCE;
- bound to this server's `/mcp` resource;
- short-lived and stored as a SHA-256 hash;
- optionally paired with a rotating refresh token;
- revocable without exposing Loystar credentials.

Production also requires PostgreSQL for OAuth/audit state, Redis for shared rate limits, HTTPS, an explicit host allowlist, Origin validation, request-size limits, an admin key, PII redaction, and disabled development surfaces.

## What is live

The production MCP endpoint advertises these read-only tools:

| Tool | Loystar data |
| --- | --- |
| `loystar_auth_status` | Connection status without secret values |
| `loystar_get_customers` | Paginated customers |
| `loystar_search_customers` | Customer search and date filtering |
| `loystar_get_sales` | Paginated sales and date filtering |
| `loystar_get_orders` | Paginated orders |
| `loystar_get_products` | Product catalogue |
| `loystar_get_product_categories` | Product categories |
| `loystar_get_loyalty_programs` | Loyalty programmes |
| `loystar_get_business_branches` | Business branches |
| `loystar_get_invoices` | Invoice search and status filtering |
| `loystar_get_sms_balance` | SMS balance |
| `loystar_get_current_subscription` | Current subscription |

Results come from the Loystar API at call time; they are not a copied demo dataset. PII fields are masked by default. A client cannot request raw PII unless the server operator explicitly enables `ALLOW_REQUEST_PII_OVERRIDE`.

## Requirements

- Python 3.10 or newer
- PostgreSQL for production
- Redis for production
- a public HTTPS domain for remote AI clients
- a Loystar merchant account for the authorization flow

## Local setup

Create a virtual environment and install the project:

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn src.main:app --reload
```

macOS/Linux:

```bash
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn src.main:app --reload
```

Open `http://localhost:8000/health`. Local development uses in-memory OAuth, audit, and rate-limit state when PostgreSQL and Redis are not configured. That mode is only for development and tests.

Run the test suite with:

```bash
python -m pytest -q
```

## Production configuration

Start from `.env.production.example`, but put secrets in the hosting platform's secret manager rather than committing a production `.env` file.

Generate independent values for the encryption and admin keys:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Run that command twice. Do not reuse either value for a database password or any other service.

### Required production variables

| Variable | Example | Purpose |
| --- | --- | --- |
| `ENVIRONMENT` | `production` | Enables fail-closed production checks |
| `MCP_SERVER_BASE_URL` | `https://loystar-mcp.example.com` | Canonical public origin; `/mcp` is added automatically |
| `OAUTH_ISSUER` | same public origin | OAuth issuer; may be left empty to use the base URL |
| `ALLOWED_HOSTS` | `loystar-mcp.example.com,healthcheck.railway.app` | Comma-separated HTTP Host allowlist; Railway healthchecks use `healthcheck.railway.app` |
| `ALLOWED_ORIGINS` | `https://admin.example.com` | Comma-separated trusted browser Origins; never use `*` |
| `DATABASE_URL` | `postgresql://...` or `postgresql+asyncpg://...` | Durable OAuth client, code, token, and audit storage; Railway's standard `DATABASE_URL` is accepted and normalized automatically |
| `REDIS_URL` | `rediss://...` | Shared atomic rate limits across workers |
| `OAUTH_ENCRYPTION_KEY` | 32+ random characters | Encrypts stored Loystar sessions |
| `ADMIN_API_KEY` | 32+ random characters | Protects the audit administration route |

### Required production safety values

```env
LOYSTAR_REDACT_PII=true
ALLOW_REQUEST_PII_OVERRIDE=false
ALLOW_ENVIRONMENT_CREDENTIALS=false

ENABLE_DEMO_ROUTES=false
ENABLE_LEGACY_ROUTES=false
ENABLE_PROTOTYPE_ROUTES=false
ENABLE_PROTOTYPE_TOOLS=false
ENABLE_BILLING_ROUTES=false
```

Production startup stops with an error if these values are unsafe. Shared `LOYSTAR_ACCESS_TOKEN`, `LOYSTAR_CLIENT`, `LOYSTAR_UID`, and `LOYSTAR_EXPIRY` values are also forbidden in production because every merchant must authorize their own account.

### OAuth settings

| Variable | Default | Notes |
| --- | --- | --- |
| `OAUTH_CODE_TTL_SECONDS` | `300` | One-time authorization-code lifetime |
| `OAUTH_TOKEN_TTL_SECONDS` | `900` | Access-token lifetime |
| `OAUTH_REFRESH_TOKEN_TTL_SECONDS` | `2592000` | Rotating refresh-token lifetime |
| `OAUTH_ALLOW_DYNAMIC_REGISTRATION` | `true` | Lets compatible MCP hosts register their callback URI |
| `OAUTH_DCR_INITIAL_ACCESS_TOKEN` | empty | Optional protection for private DCR; many public AI clients cannot supply it |
| `OAUTH_STATIC_CLIENTS_JSON` | `[]` | Pre-registered clients when dynamic registration is disabled |

Example static public client:

```env
OAUTH_ALLOW_DYNAMIC_REGISTRATION=false
OAUTH_STATIC_CLIENTS_JSON=[{"client_id":"my-ai-client","client_name":"My AI Client","redirect_uris":["https://client.example.com/oauth/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}]
```

Redirect URIs must match exactly. HTTPS is required, except for loopback HTTP redirects used in local native-client development.

The bridge refresh token rotates access to the stored Loystar session; it does
not extend that upstream Loystar session. When Loystar expires the merchant
session, the merchant must reconnect.

### Loystar API settings

| Variable | Default |
| --- | --- |
| `LOYSTAR_API_BASE_URL` | `https://api.loystar.co` |
| `LOYSTAR_API_V1_BASE_URL` | `https://api1.loystar.co` |
| `LOYSTAR_TIMEOUT_SECONDS` | `20` |
| `LOYSTAR_REDACT_PII` | `true` |
| `ALLOW_REQUEST_PII_OVERRIDE` | `false` |

No OpenAI, Anthropic, or Perplexity API key is required. The AI host supplies the model; this service supplies authenticated Loystar tools.

### Network and operational settings

| Variable | Default | Notes |
| --- | --- | --- |
| `MCP_SERVER_HOST` | `127.0.0.1` | Use `0.0.0.0` in a container |
| `MCP_SERVER_PORT` | `8000` | Railway uses its injected `PORT` |
| `TRUST_PROXY_HEADERS` | `false` | Set true only behind a trusted HTTPS reverse proxy |
| `MAX_REQUEST_BODY_BYTES` | `1048576` | Maximum HTTP body size |
| `RATE_LIMIT_REQUESTS` | `60` | MCP requests per window and identity |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Rate-limit window |
| `OAUTH_RATE_LIMIT_REQUESTS` | `20` | OAuth requests per window and identity |
| `AUDIT_LOG_MAX_EVENTS` | `500` | Maximum rows returned by admin audit reads |
| `REQUIRE_CONNECTOR_AUTH` | `false` | Optional gateway-to-gateway key; normal MCP clients use OAuth |
| `CONNECTOR_API_KEY` | empty | Sent as `x-connector-api-key` only when the extra gateway check is enabled |

Do not enable `REQUIRE_CONNECTOR_AUTH` for a normal direct AI connection unless that client can send the custom header.

## Database setup and upgrades

On a new empty database, the service creates its tables at startup.

If the database was used by an older version of this repository, run:

```bash
psql YOUR_POSTGRES_CONNECTION_URL -f migrations/001_secure_oauth.sql
```

This migration deliberately deletes old authorization codes and tokens because their earlier schema did not meet the new security model. Existing merchants must reconnect once after the upgrade. Back up the database and run the migration during a maintenance window.

## Deploying

The repository includes a Railway configuration. A production release needs:

1. a PostgreSQL service;
2. a Redis service;
3. the values from `.env.production.example`;
4. a stable HTTPS domain;
5. the secure OAuth migration if this is an upgrade;
6. a deploy followed by readiness and end-to-end OAuth tests.

The Railway configuration starts one worker by default for predictable connection usage. PostgreSQL and Redis are mandatory in production; if you later scale to multiple workers/replicas, durable PostgreSQL/Redis state keeps OAuth and rate limits shared.

### Railway deployment

Railway provides managed PostgreSQL and Redis services and exposes `DATABASE_URL` and `REDIS_URL` to services through variables.

1. Create a Railway project.
2. Add PostgreSQL and Redis services.
3. Deploy this repository as the web service.
4. Reference the database variables from the app service:
   - `DATABASE_URL=${{Postgres.DATABASE_URL}}`
   - `REDIS_URL=${{Redis.REDIS_URL}}`
5. Generate a public domain under the service's networking settings.
6. Set `MCP_SERVER_BASE_URL` and `OAUTH_ISSUER` to that exact HTTPS origin.
7. Set `ALLOWED_HOSTS` to the public hostname plus `healthcheck.railway.app`.
8. Set the production safety variables from `.env.production.example`.
9. Keep the Railway healthcheck path at `/health`.

Railway injects `PORT`, and its healthcheck waits for `/health` to return HTTP 200 before routing the deployment. The Railway healthcheck hostname is `healthcheck.railway.app`, so it must be permitted by the application's host allowlist.

For CLI deployment, Railway's documented command for deploying application code is `railway up`.

After deployment, check:

```bash
curl https://loystar-mcp.example.com/live
curl https://loystar-mcp.example.com/health
curl https://loystar-mcp.example.com/.well-known/oauth-protected-resource
curl https://loystar-mcp.example.com/.well-known/oauth-authorization-server
```

`/live` checks the process. `/health` is the readiness endpoint and returns `503` in production if PostgreSQL or Redis is unavailable.

## Connecting ChatGPT, Claude, Perplexity, or another MCP client

Use this remote MCP URL:

```text
https://loystar-mcp.example.com/mcp
```

In the client's connector or custom-app settings:

1. create a remote MCP connection;
2. choose Streamable HTTP and OAuth when those options are shown;
3. enter the public `/mcp` URL;
4. complete the Loystar authorization screen;
5. approve read access for the correct merchant account;
6. test with `Show me my latest Loystar sales`.

Menus and account-plan requirements differ by provider and change over time. The important integration contract is the public `/mcp` URL plus the discovery endpoints below.

## MCP and OAuth endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/mcp` | MCP 2025-11-25 Streamable HTTP JSON-RPC |
| `GET` | `/.well-known/oauth-protected-resource` | RFC 9728 resource metadata |
| `GET` | `/.well-known/oauth-protected-resource/mcp` | Path-specific resource metadata |
| `GET` | `/.well-known/oauth-authorization-server` | OAuth server metadata |
| `POST` | `/oauth/register` | Dynamic client registration when enabled |
| `GET`, `POST` | `/oauth/authorize` | Merchant consent and Loystar sign-in |
| `POST` | `/oauth/token` | Code exchange and refresh-token rotation |
| `POST` | `/oauth/revoke` | Token revocation |
| `GET` | `/health` | Dependency-aware readiness |
| `GET` | `/live` | Process liveness |
| `GET` | `/admin/audit/events` | Sanitized audit trail; requires `x-admin-api-key` |

The development-only demo, legacy MCP helpers, billing, prototype resources, and simulated write tools return `404` in the production profile.

## Manual MCP check

Initialization does not require merchant authorization:

```bash
curl -X POST https://loystar-mcp.example.com/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"manual-check","version":"1.0"}}}'
```

Data tools require an OAuth access token issued for the exact MCP resource:

```bash
curl -X POST https://loystar-mcp.example.com/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer REPLACE_WITH_ACCESS_TOKEN" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"loystar_get_sales","arguments":{"page_number":1,"page_size":10}}}'
```

Avoid putting real credentials in shared shell history.

## Security notes

- OAuth codes, access tokens, refresh tokens, Loystar credentials, and tool results are never written to the audit log.
- Access and refresh tokens are opaque, random, hashed at rest, audience-bound, and revocable.
- Refresh tokens rotate; reusing an old one fails.
- Stored Loystar sessions are encrypted and separated by merchant authorization.
- Production CORS and Host settings do not accept wildcards.
- Browser Origins are checked on MCP requests to reduce DNS-rebinding risk.
- Tool input rejects unknown properties and enforces size/range limits.
- Production tools are read-only and carry MCP read-only annotations.
- Secret rotation for `OAUTH_ENCRYPTION_KEY` requires a planned merchant reconnect unless old ciphertext is migrated first.

This code still needs normal production operations: secret management, database backups, TLS/domain ownership, uptime and error monitoring, dependency patching, incident response, and a security review appropriate to the data being processed. Passing the included tests is not a substitute for testing the deployed service with each AI provider you intend to support.

## Project layout

```text
src/main.py                 FastAPI app, OAuth routes, MCP transport
src/server.py               MCP protocol, schemas, and tool registry
src/loystar_client.py       Merchant-scoped Loystar API client
src/oauth_store.py          OAuth clients, codes, token rotation/revocation
src/security.py             Redis rate limits and sanitized audit logging
src/http_security.py        Host, Origin, HTTPS, header, and body controls
src/database.py             Async PostgreSQL lifecycle
src/models.py               PostgreSQL models
migrations/                 Production database upgrades
tests/unit/                 Protocol and security tests
```

## Current status

This repository now implements the same core product category as a permissioned business-data MCP bridge: merchant consent, live account-scoped data, remote MCP transport, OAuth, durable security state, and revocation. It is an independent Loystar implementation and does not claim feature-for-feature parity, certification, or affiliation with Tyms or any other MCP server.
#   l o y s t a r  
 