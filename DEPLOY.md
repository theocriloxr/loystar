# Production deployment

The maintained deployment instructions are in [README.md](README.md#deploying).

Do not deploy using the old demo defaults. Production requires PostgreSQL,
Redis, HTTPS, the full `.env.production.example` safety profile, and the secure
OAuth migration for an existing database.

Release gate:

```bash
python -m pytest -q
python -m compileall src scripts
python scripts/mcp_smoke_test.py --base-url https://loystar-production.up.railway.app
```

Then verify `/live`, `/health`, both OAuth discovery documents, one complete
authorization-code/PKCE flow, refresh-token rotation, revocation, and one live
Loystar read from every AI client you intend to support.

The canonical production origin and issuer are both
`https://loystar-production.up.railway.app`; the protected resource is that
origin plus `/mcp`. Keep `OAUTH_ENABLE_CIMD=true` only while the CIMD tests pass.
An unauthenticated MCP initialize request must return `401` with a
`WWW-Authenticate` `resource_metadata` link. `POST /` remains `405`, and the
stateless transport does not use `GET /mcp` for fake discovery data.
