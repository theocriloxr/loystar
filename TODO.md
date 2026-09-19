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

## Production verification

- [x] Railway PostgreSQL and Redis services are provisioned
- [x] Production MCP service is deployed from `main`
- [x] Public HTTPS endpoint is live at `https://loystar-production.up.railway.app`
- [x] OAuth issuer and protected-resource discovery resolve to the production origin
- [x] Health checks report PostgreSQL and Redis ready
- [x] Dynamic client registration and unauthenticated OAuth discovery are covered by the remote smoke test
- [x] ChatGPT/Codex portable plugin package is present in the repository
- [ ] Complete a real merchant sign-in from each intended AI host
- [ ] Verify at least one live merchant read tool end to end with authorized data
- [ ] Record live refresh-token rotation and revocation against an authorized merchant session

## Future product phases

- [ ] Add merchant-authorized write tools behind HITL approval
- [ ] Add durable approval queue/state machine
- [ ] Add richer customer analytics and RFM/churn models
- [ ] Add Stripe/Paystack write integrations after the read-only production phase
- [ ] Add observability/alerting beyond the audit endpoint
