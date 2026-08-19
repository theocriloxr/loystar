# Loystar MCP Server — completion checklist

The original phase checklist is retained below as historical context. The current
repository is a production-oriented, read-only remote MCP bridge with OAuth,
merchant-scoped credentials, encrypted PostgreSQL state, Redis rate limiting,
audit logging, and Railway deployment support.

## Completed

- [x] FastAPI HTTP service and JSON-RPC 2.0 MCP transport
- [x] MCP `initialize`, `ping`, `tools/list`, `tools/call`, and notifications
- [x] Streamable HTTP endpoint at `POST /mcp`
- [x] MCP protocol-version negotiation for supported 2025 revisions
- [x] Loystar merchant-scoped read tools
- [x] PII redaction by default
- [x] OAuth 2.1-style authorization-code + S256 PKCE flow
- [x] OAuth discovery metadata
- [x] Rotating access/refresh tokens and revocation
- [x] AES-GCM encryption for stored Loystar sessions
- [x] PostgreSQL-backed OAuth/audit state
- [x] Redis-backed shared rate limiting
- [x] Production security middleware and fail-closed configuration
- [x] Railway health/liveness endpoints
- [x] Automated unit coverage for MCP, OAuth, security, and demo flows
- [x] Railway-friendly PostgreSQL URL normalization

## Before the first real merchant deployment

- [ ] Create Railway PostgreSQL and Redis services
- [ ] Deploy the MCP service and generate a public HTTPS domain
- [ ] Set production variables from `.env.production.example`
- [ ] Set `MCP_SERVER_BASE_URL` and `OAUTH_ISSUER` to the exact public origin
- [ ] Add the public domain and `healthcheck.railway.app` to `ALLOWED_HOSTS`
- [ ] Complete the OAuth connection from a real MCP host
- [ ] Connect a real Loystar merchant and verify at least one live read tool
- [ ] Test token refresh and revocation
- [ ] Record a live AI-client smoke test

## Future product phases

- [ ] Add merchant-authorized write tools behind HITL approval
- [ ] Add durable approval queue/state machine
- [ ] Add richer customer analytics and RFM/churn models
- [ ] Add Stripe/Paystack write integrations after the read-only production phase
- [ ] Add observability/alerting beyond the audit endpoint
