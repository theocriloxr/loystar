# Executive Summary: Loystar MCP Server

> Historical product summary. Use `README.md` for the current production
> architecture, configuration, security guarantees, and release status.

## One-Sentence Product Statement

**A multi-tenant, zero-knowledge MCP server that lets merchants query their Loystar business data through ChatGPT, Claude, or any AI — using their Loystar login, not API keys.**

---

## What It Solves

| Problem | Solution |
|---------|----------|
| Merchants can't easily ask AI about their business data | They connect the MCP server to any AI platform once, then ask questions in plain English |
| API keys are complex and insecure for non-technical merchants | OAuth with Loystar credentials — no API keys needed |
| AI platforms can't safely access multi-tenant data | Every tool call is scoped to one merchant's session |
| Sensitive data (PII) could leak | Automatic PII masking before data reaches the AI |
| No audit trail for AI actions | Full audit logging of every tool call with merchant identity |

---

## Architecture

```
Merchant → Any AI (ChatGPT/Claude/Gemini/etc.) → OAuth Login → Loystar MCP Server → Loystar API
                              │                   │
                          Bearer Token      Security Layer:
                          per merchant      • Rate Limiting
                                            • PII Redaction
                                            • Audit Logging
                                            • HITL Guardrails
```

---

## Key Capabilities

### AI Platform Support
- **ChatGPT** (web + desktop) — native MCP support
- **Claude** (desktop + code) — native MCP support
- **Any MCP client** — Cursor, Windsurf, LangGraph, custom agents

### Merchant Data Access
Merchants can ask their AI about:
- Customers, sales, orders, products, categories
- Invoices, loyalty programs, business branches
- SMS balance, subscription details
- Churn risk analysis, coupon generation, messaging

### Security Measures Implemented

| Measure | Implementation |
|---------|---------------|
| **Multi-tenant isolation** | Bearer token → single merchant session |
| **PII redaction** | Email/phone masked by default |
| **Audit logging** | Every tool call logged with merchant identity |
| **Rate limiting** | 60 req/min per merchant configurable |
| **Connector auth** | Optional API key for server-to-server auth |
| **Write guardrails** | HITL for actions over $100 financial exposure |
| **OAuth 2.0 with PKCE** | Standard secure auth flow |
| **No password storage** | Password cleared after session exchange |
| **Short-lived tokens** | 1-hour bearer token lifetime |

### MCP Protocol Compliance
- ✅ Streamable HTTP transport (`POST /mcp`)
- ✅ SSE transport (`GET /mcp`)
- ✅ Standard lifecycle (`initialize`, `ping`, `notifications/initialized`)
- ✅ Tool discovery (`tools/list`) and execution (`tools/call`)
- ✅ Resource discovery (`resources/list`) and reading (`resources/read`)
- ✅ OAuth 2.0 with PKCE (`.well-known/oauth-*`, `/oauth/*`)

---

## How Merchants Set It Up

**No developer needed. No API keys. The merchant:**

1. Opens **their AI platform of choice** (chatgpt.com, claude.ai, etc.)
2. Adds the Loystar MCP server URL in the platform's MCP Server settings
3. Signs in with their **Loystar email and password** once via OAuth
4. Starts asking questions in natural language

**That's it.** Three steps, zero code, zero API keys, works with any AI.

---

## Security Design: Zero-Knowledge Architecture

The server is designed as a **zero-knowledge proxy**:

1. **The AI never sees Loystar credentials** — they're stored as a session token on the server
2. **PII is masked before leaving the server** — the AI gets `me***@domain.com` instead of the full email
3. **Every request is rate-limited and audited** — no silent data exfiltration
4. **Write actions require human approval** — no AI can create coupons or send messages without the merchant confirming

---

## Cybersecurity Posture

| Category | Controls |
|----------|----------|
| **Authentication** | OAuth 2.0 with PKCE, optional connector API key, JWT session signing |
| **Authorization** | Per-request merchant scoping via bearer tokens |
| **Data protection** | PII redaction, no credential storage |
| **Rate limiting** | Fixed-window per-merchant rate limiter |
| **Auditing** | Complete audit trail with merchant identity, tool name, status, IP, timestamp |
| **Transport** | HTTPS required (Railway auto-HTTPS) |
| **Input validation** | Pydantic models on all endpoints |
| **Error handling** | Structured JSON-RPC errors, no stack traces in production |
| **CORS** | Fully configurable CORS middleware |

---

## Deployment Options

| Platform | Ease | Cost | Notes |
|----------|------|------|-------|
| **Railway** | ⭐⭐⭐⭐⭐ | Free tier available | One-click deploy from GitHub |
| **Docker** | ⭐⭐⭐⭐ | Variable | Full control, any cloud |
| **Vercel** | ⭐⭐⭐ | Free tier (limited) | 60s timeout, ephemeral storage |

### Quick Deploy (Railway)

1. Push to GitHub
2. Railway → New Project → Deploy from GitHub
3. Add env vars (`MCP_SERVER_BASE_URL`, `JWT_SECRET_KEY`)
4. Done — 5 minutes total

---

## Tests

**27 tests passing, 0 failures** — covering:
- MCP protocol flow (initialize, tools/list, tools/call)
- OAuth linking flow (authorize, token exchange, bearer validation)
- Natural language to tool mapping
- Loystar credential extraction and session headers
- API key enforcement
- Rate limiting
- Audit logging
- CORS headers

---

## Follow-Up Roadmap

### Phase 1: Persistent OAuth Store (Next Sprint)
Replace in-memory OAuth with encrypted PostgreSQL. Tokens survive restarts, scale to thousands of merchants, enable refresh/revocation.

### Phase 2: Self-Serve Billing (2 Sprints)
Add Stripe/Paddle integration. Merchants deploy → pick plan → pay → connect Loystar → get MCP URL. Zero-touch onboarding.

### Phase 3: Custom GPT / AI App Store Listings (3 Sprints)
Publish pre-configured Custom GPTs for ChatGPT, Claude MCP integration, and Gemini connectors. Merchants just open and talk.

---

## Appendix: AI Used in This Review

This project and its documentation were reviewed with the assistance of:
- **Claude 3.5 Sonnet** (via Codebuff) — code architecture review
- **DeepSeek Flash** — code review and security analysis
- **GPT-4o** — documentation and executive summary composition

All AI-assisted reviews were focused on code correctness, security posture, and architectural soundness. No proprietary or customer data was shared with any AI system during review.
