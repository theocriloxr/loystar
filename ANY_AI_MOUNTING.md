# Mount Loystar In Any AI System

> Historical integration notes. The security and deployment details here are
> superseded by `README.md`, which documents the current production profile.

This server exposes one remote MCP endpoint:

```
https://YOUR_PUBLIC_DOMAIN/mcp
```

Any AI client that supports remote MCP — ChatGPT, Claude Code, Cursor, Windsurf, LangGraph agents — can use the same Loystar connector.

**No API keys needed. Merchants authenticate with their Loystar credentials via OAuth.**

---

## The User Experience

1. Merchant opens their AI system (chatgpt.com, claude.ai, etc.)
2. They add the Loystar MCP server URL
3. The protected `/mcp` endpoint challenges the host and starts OAuth discovery
4. After OAuth completes, the AI host initializes MCP and discovers Loystar tools
5. Merchant sees the Loystar login page (served by this server)
6. Merchant enters their Loystar email/password
7. Server exchanges login for Loystar session headers
8. Server gives the AI host a short-lived bearer token
9. AI host calls `/mcp` with that bearer token
10. Merchant asks normal questions in natural language
11. AI answers using real-time Loystar data — **only that merchant's data**

**This is exactly how ChatGPT and Claude work natively with remote MCP servers.**

---

## ChatGPT Setup

### Desktop App (macOS/Windows)

1. Open **ChatGPT Desktop**
2. Go to **Settings** → **Developer** → **MCP Servers**
3. Click **Add MCP Server**
4. Configure:
   - **Name:** `Loystar`
   - **Type:** `Remote MCP`
   - **URL:** `https://YOUR_PUBLIC_DOMAIN/mcp`
5. ChatGPT auto-discovers OAuth metadata from `/.well-known/oauth-protected-resource`
6. When the merchant asks their first question, ChatGPT redirects them to the Loystar login page
7. After sign-in, ChatGPT stores the bearer token

### Web (chatgpt.com)

1. Go to **Settings** → **MCP Servers**
2. Add server with URL: `https://YOUR_PUBLIC_DOMAIN/mcp`
3. Same OAuth flow triggers automatically

---

## Claude Setup

### Claude Code (CLI)

```bash
claude mcp add loystar --type remote --url https://YOUR_PUBLIC_DOMAIN/mcp
```

### Claude Desktop

1. Open **Claude Desktop**
2. Go to **Settings** → **Developer** → **MCP Servers**
3. Add remote server:
   ```json
   {
     "mcpServers": {
       "Loystar": {
         "type": "remote",
         "url": "https://YOUR_PUBLIC_DOMAIN/mcp"
       }
     }
   }
   ```
4. Claude auto-discovers the OAuth flow

---

## Supported AI Platforms

| Platform | MCP Support | Auth Method |
|----------|-------------|-------------|
| **ChatGPT** (web + desktop) | ✅ Native | OAuth 2.0 |
| **Claude** (desktop + code) | ✅ Native | OAuth 2.0 |
| **Cursor** | ✅ Native | OAuth 2.0 |
| **Windsurf** | ✅ Native | OAuth 2.0 |
| **Gemini** | Via function calling | API Key |
| **LangGraph / LangChain** | ✅ Via MCP adapter | OAuth 2.0 |
| **Custom agents** | ✅ `/mcp` or `/mcp/rpc` | Bearer token |

---

## Required Public URLs

These must be publicly accessible and HTTPS:

```
GET  https://YOUR_PUBLIC_DOMAIN/health
POST https://YOUR_PUBLIC_DOMAIN/mcp
GET  https://YOUR_PUBLIC_DOMAIN/.well-known/oauth-protected-resource
GET  https://YOUR_PUBLIC_DOMAIN/.well-known/oauth-authorization-server
GET  https://YOUR_PUBLIC_DOMAIN/oauth/authorize
POST https://YOUR_PUBLIC_DOMAIN/oauth/token
```

---

## MCP Protocol Flow

```
1. Client sends initialize without a token and receives an OAuth challenge:
   â† 401 WWW-Authenticate: Bearer resource_metadata="...", scope="loystar.read"

2. After OAuth, client sends authenticated initialize:
   → {"jsonrpc":"2.0","id":1,"method":"initialize",...}
   ← {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26",...}}

3. Client sends initialized notification:
   → {"jsonrpc":"2.0","method":"notifications/initialized"}

4. Client discovers tools:
   → {"jsonrpc":"2.0","id":2,"method":"tools/list"}
   ← {"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"loystar_get_customers",...}]}}

5. Client calls a tool:
   → {"jsonrpc":"2.0","id":3,"method":"tools/call",
      "params":{"name":"loystar_get_sales","arguments":{"page_number":1,"page_size":10}}}
   ← {"jsonrpc":"2.0","id":3,"result":{"source":"loystar_api","data":{...}}}
```

---

## OAuth Flow Detail

```
1. Client calls tool without auth
   401 WWW-Authenticate: Bearer resource_metadata="...", scope="loystar.read"

2. Client fetches OAuth metadata:
   GET /.well-known/oauth-protected-resource
   → {"resource":"https://.../mcp","authorization_servers":["..."],"scopes_supported":["loystar.read"]}

3. Client redirects user to:
   GET /oauth/authorize?response_type=code&client_id=...&redirect_uri=...&code_challenge=...

4. User signs in with Loystar credentials
   POST /oauth/authorize (email + password)
   ← 302 Redirect to redirect_uri?code=loy_code_xxx

5. Client exchanges code for token:
   POST /oauth/token
   grant_type=authorization_code&code=loy_code_xxx&code_verifier=...
   ← {"access_token":"loy_at_xxx","token_type":"Bearer","expires_in":3600}

6. Subsequent tool calls include:
   Authorization: Bearer loy_at_xxx
```

---

## Multi-Tenant Security

Every bearer token maps to **exactly one merchant's Loystar session**. Tool calls using that token can only access that merchant's data. There is no shared namespace, no global API key, and no way for one merchant to access another's data.

---

## Legacy Endpoints

For AI platforms that don't support MCP natively:

| Endpoint | Purpose |
|----------|---------|
| `POST /mcp/rpc` | JSON-RPC 2.0 for custom agents |
| `POST /mcp/tools/call` | Simple tool call endpoint |
| `GET /mcp/tools` | Tool discovery |
| `GET /demo` | Browser-based AI host simulator |

---

## Demo Questions

Once connected, the merchant can ask:

```
Show my latest customers
What were my sales last month?
List my products and inventory
Show unpaid invoices
Which customers look inactive or at churn risk?
What loyalty programs are active?
What are my business branches?
How many SMS credits do I have?
What is my current subscription plan?
Search for customer John
```

The AI maps natural language to the appropriate Loystar tool automatically.

---

## Production Notes

- Production requires PostgreSQL-backed OAuth state and AES-256-GCM encrypted Loystar sessions.
- Use HTTPS everywhere and set the exact canonical origin in both `MCP_SERVER_BASE_URL` and `OAUTH_ISSUER`.
- Keep `REQUIRE_CONNECTOR_AUTH=false` for normal ChatGPT/Claude OAuth connections.
- Keep `ALLOW_ENVIRONMENT_CREDENTIALS=false`; each token is bound to one merchant session.
- DCR and validated CIMD are both supported; redirect URIs always match exactly.
- Refresh tokens rotate, and reuse of the previous token is rejected.
- Keep `LOYSTAR_REDACT_PII=true` and never log OAuth or Loystar credentials.

To reconnect after a deployment or upstream Loystar-session expiry, remove or
disconnect the Loystar MCP entry in the AI client's connector settings, add
`https://loystar-production.up.railway.app/mcp` again, and complete the Loystar
login/consent screen. A `400` from `/oauth/authorize` indicates invalid client,
redirect, scope, PKCE, prompt, or resource parameters; a `401` from `/mcp` is the
expected pre-authentication discovery challenge.
